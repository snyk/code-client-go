/*
 * © 2024 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//nolint:lll // Some of the lines in this file are going to be long for now.
package analysis

import (
	"context"
	_ "embed"
	"encoding/json"
	goerrors "errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	errors "github.com/pkg/errors"
	"github.com/rs/zerolog"

	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/config"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/internal/analysis/sanitizers"
	testApi "github.com/snyk/code-client-go/internal/api/test/2025-04-07"
	testModels "github.com/snyk/code-client-go/internal/api/test/2025-04-07/models"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
	"github.com/snyk/error-catalog-golang-public/cli"
)

//go:generate go tool github.com/golang/mock/mockgen -destination=mocks/analysis.go -source=analysis.go -package mocks

type AnalysisOrchestrator interface {
	RunTest(ctx context.Context, orgId string, b bundle.Bundle, target scan.Target, reportingOptions AnalysisConfig) (*sarif.SarifResponse, *scan.ResultMetaData, error)
	RunTestRemote(ctx context.Context, orgId string, reportingOptions AnalysisConfig) (*sarif.SarifResponse, *scan.ResultMetaData, error)
	RunDiscoverTest(ctx context.Context, orgId string, b bundle.Bundle, target scan.Target) (*sanitizers.Document, error)
	RunLegacyTest(ctx context.Context, bundleHash string, shardKey string, limitToFiles []string, severity int) (*sarif.SarifResponse, scan.LegacyScanStatus, error)
}

type AnalysisConfig struct {
	Report          bool
	ProjectName     *string
	ProjectTags     *[]string
	TargetName      *string
	TargetReference *string
	ProjectId       *uuid.UUID
	CommitId        *string
}

type analysisOrchestrator struct {
	httpClient     codeClientHTTP.HTTPClient
	instrumentor   observability.Instrumentor
	errorReporter  observability.ErrorReporter
	logger         *zerolog.Logger
	trackerFactory scan.TrackerFactory
	config         config.Config
	testType       testModels.ResultType
}

var _ AnalysisOrchestrator = (*analysisOrchestrator)(nil)

type OptionFunc func(*analysisOrchestrator)

func WithInstrumentor(instrumentor observability.Instrumentor) func(*analysisOrchestrator) {
	return func(a *analysisOrchestrator) {
		a.instrumentor = instrumentor
	}
}

func WithErrorReporter(errorReporter observability.ErrorReporter) func(*analysisOrchestrator) {
	return func(a *analysisOrchestrator) {
		a.errorReporter = errorReporter
	}
}

func WithLogger(logger *zerolog.Logger) func(*analysisOrchestrator) {
	return func(a *analysisOrchestrator) {
		a.logger = logger
	}
}

func WithTrackerFactory(factory scan.TrackerFactory) func(*analysisOrchestrator) {
	return func(a *analysisOrchestrator) {
		a.trackerFactory = factory
	}
}

func WithResultType(t testModels.ResultType) func(*analysisOrchestrator) {
	return func(a *analysisOrchestrator) {
		a.testType = t
	}
}

func NewAnalysisOrchestrator(
	config config.Config,
	httpClient codeClientHTTP.HTTPClient,
	options ...OptionFunc,
) AnalysisOrchestrator {
	nopLogger := zerolog.Nop()

	a := &analysisOrchestrator{
		httpClient:     httpClient,
		config:         config,
		instrumentor:   observability.NewInstrumentor(),
		trackerFactory: scan.NewNoopTrackerFactory(),
		errorReporter:  observability.NewErrorReporter(&nopLogger),
		logger:         &nopLogger,
		testType:       testModels.CodeSecurityCodeQuality,
	}

	for _, option := range options {
		option(a)
	}

	return a
}

func (a *analysisOrchestrator) retrieveFindings(ctx context.Context, scanJobId uuid.UUID, findingsUrl string) (*sarif.SarifResponse, error) {
	method := "analysis.retrieveFindings"
	logger := a.logger.With().Str("method", method).Logger()
	logger.Debug().Str("scanJobId", scanJobId.String()).Msg("retrieving findings from URL for scan job")

	if findingsUrl == "" {
		return nil, errors.New("do not have a findings URL")
	}
	req, err := http.NewRequest(http.MethodGet, findingsUrl, nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	rsp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rsp.Body.Close() }()
	bodyBytes, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, err
	}

	if rsp.StatusCode != http.StatusOK {
		return nil, errors.New("failed to retrieve findings from findings URL")
	}

	var sarifDocument sarif.SarifDocument
	err = json.Unmarshal(bodyBytes, &sarifDocument)
	if err != nil {
		return nil, err
	}

	return &sarif.SarifResponse{
		Type:     "sarif",
		Progress: 1,
		Status:   "COMPLETE",
		Sarif:    sarifDocument,
	}, nil
}

func (a *analysisOrchestrator) host(isHidden bool) string {
	apiUrl := strings.TrimRight(a.config.SnykApi(), "/")
	// Temporary Workaround because intellij currently adds a /v1 suffix to the EndpointAPI
	apiUrl = strings.Replace(apiUrl, "/v1", "", 1)
	path := "rest"
	if isHidden {
		path = "hidden"
	}
	return fmt.Sprintf("%s/%s", apiUrl, path)
}

func repoTargetFields(target scan.Target) (commitId, repoUrl, branchName *string) {
	if repoTarget, ok := target.(*scan.RepositoryTarget); ok {
		if u := repoTarget.GetRepositoryUrl(); len(u) > 0 {
			repoUrl = &u
		}
		if c := repoTarget.GetCommitId(); len(c) > 0 {
			commitId = &c
		}
		if b := repoTarget.GetBranchName(); len(b) > 0 {
			branchName = &b
		}
	}
	return
}

func (a *analysisOrchestrator) createTestAndGetResults(ctx context.Context, orgId string, body *testApi.CreateTestApplicationVndAPIPlusJSONRequestBody, progressString string) (*sarif.SarifResponse, *scan.ResultMetaData, error) {
	tracker := a.trackerFactory.GenerateTracker()
	tracker.Begin(progressString, "Retrieving results...")

	client, orgUuid, testId, err := a.submitTest(ctx, orgId, body)
	if err != nil {
		tracker.End("Analysis failed.")
		return nil, nil, err
	}

	result, metadata, err := a.pollTestForFindings(ctx, client, orgUuid, testId)
	if err != nil {
		tracker.End("Analysis failed.")
		return nil, nil, err
	}

	tracker.End("Analysis completed.")
	return result, metadata, nil
}

func (a *analysisOrchestrator) submitTest(ctx context.Context, orgId string, body *testApi.CreateTestApplicationVndAPIPlusJSONRequestBody) (*testApi.Client, uuid.UUID, openapi_types.UUID, error) {
	params := testApi.CreateTestParams{Version: testApi.ApiVersion}
	orgUuid := uuid.MustParse(orgId)

	client, err := testApi.NewClient(a.host(true), testApi.WithHTTPClient(a.httpClient))
	if err != nil {
		return nil, uuid.UUID{}, openapi_types.UUID{}, err
	}

	resp, err := client.CreateTestWithApplicationVndAPIPlusJSONBody(ctx, orgUuid, &params, *body)
	if err != nil {
		return nil, uuid.UUID{}, openapi_types.UUID{}, err
	}

	parsedResponse, err := testApi.ParseCreateTestResponse(resp)
	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			a.logger.Err(closeErr).Msg("failed to close response body")
		}
	}()
	if err != nil {
		return nil, uuid.UUID{}, openapi_types.UUID{}, err
	}

	if parsedResponse.StatusCode() != http.StatusCreated {
		return nil, uuid.UUID{}, openapi_types.UUID{}, fmt.Errorf("create test: unexpected status %d", parsedResponse.StatusCode())
	}

	return client, orgUuid, parsedResponse.ApplicationvndApiJSON201.Data.Id, nil
}

func (a *analysisOrchestrator) RunTest(ctx context.Context, orgId string, b bundle.Bundle, target scan.Target, reportingConfig AnalysisConfig) (*sarif.SarifResponse, *scan.ResultMetaData, error) {
	commitId, repoUrl, branchName := repoTargetFields(target)

	body := testApi.NewCreateTestApplicationBody(
		testApi.WithInputBundle(b.GetBundleHash(), target.GetPath(), repoUrl, b.GetLimitToFiles(), commitId, branchName),
		testApi.WithScanType(a.testType),
		testApi.WithProjectName(reportingConfig.ProjectName),
		testApi.WithProjectTags(reportingConfig.ProjectTags),
		testApi.WithTargetName(reportingConfig.TargetName),
		testApi.WithTargetReference(reportingConfig.TargetReference),
		testApi.WithReporting(&reportingConfig.Report),
	)

	return a.createTestAndGetResults(ctx, orgId, body, "Snyk Code analysis for "+target.GetPath())
}

func (a *analysisOrchestrator) RunTestRemote(ctx context.Context, orgId string, cfg AnalysisConfig) (*sarif.SarifResponse, *scan.ResultMetaData, error) {
	if cfg.ProjectId == nil || cfg.CommitId == nil {
		return nil, nil, errors.New("projectId and commitId are required")
	}

	legacyScmProject := testApi.NewTestInputLegacyScmProject(*cfg.ProjectId, *cfg.CommitId)
	body := testApi.NewCreateTestApplicationBody(
		testApi.WithInputLegacyScmProject(legacyScmProject),
		testApi.WithReporting(&cfg.Report),
		testApi.WithScanType(a.testType),
		testApi.WithProjectId(*cfg.ProjectId),
	)

	return a.createTestAndGetResults(ctx, orgId, body, "Snyk Code analysis for remote project")
}

func (a *analysisOrchestrator) RunDiscoverTest(ctx context.Context, orgId string, b bundle.Bundle, target scan.Target) (*sanitizers.Document, error) {
	commitId, repoUrl, branchName := repoTargetFields(target)

	body := testApi.NewCreateTestApplicationBody(
		testApi.WithInputBundle(b.GetBundleHash(), target.GetPath(), repoUrl, b.GetLimitToFiles(), commitId, branchName),
		testApi.WithDiscoverScanConfig(),
	)

	tracker := a.trackerFactory.GenerateTracker()
	tracker.Begin("Custom-sanitizer discovery for "+target.GetPath(), "Retrieving results...")

	client, orgUuid, testId, err := a.submitTest(ctx, orgId, body)
	if err != nil {
		tracker.End("Discovery failed.")
		return nil, err
	}

	doc, err := a.pollTestForDiscovery(ctx, client, orgUuid, testId)
	if err != nil {
		tracker.End("Discovery failed.")
		return nil, err
	}

	tracker.End("Discovery completed.")
	return doc, nil
}

func (a *analysisOrchestrator) pollUntilTestComplete(ctx context.Context, client *testApi.Client, org uuid.UUID, testId openapi_types.UUID, timeoutMsg string) error {
	method := "analysis.pollUntilTestComplete"
	logger := a.logger.With().Str("method", method).Logger()

	pollingTicker := time.NewTicker(1 * time.Second)
	defer pollingTicker.Stop()
	timeoutTimer := time.NewTimer(a.config.SnykCodeAnalysisTimeout())
	defer timeoutTimer.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeoutTimer.C:
			logger.Error().Str("scanJobId", testId.String()).Msg(timeoutMsg)
			return fmt.Errorf("%s: %w", timeoutMsg, context.DeadlineExceeded)
		case <-pollingTicker.C:
			completed, err := a.isTestComplete(ctx, client, org, testId)
			if err != nil {
				return err
			}
			if completed {
				return nil
			}
		}
	}
}

func (a *analysisOrchestrator) isTestComplete(ctx context.Context, client *testApi.Client, org uuid.UUID, testId openapi_types.UUID) (bool, error) {
	method := "analysis.isTestComplete"
	logger := a.logger.With().Str("method", method).Logger()
	logger.Debug().Msg("polling test result")

	httpResponse, err := client.GetTestResult(
		ctx,
		org,
		testId,
		&testApi.GetTestResultParams{Version: testApi.ApiVersion},
	)
	if err != nil {
		logger.Err(err).Str("testId", testId.String()).Msg("error requesting the test result")
		return false, err
	}
	defer func() {
		closeErr := httpResponse.Body.Close()
		if closeErr != nil {
			a.logger.Err(closeErr).Msg("failed to close response body")
		}
	}()

	parsedResponse, err := testApi.ParseGetTestResultResponse(httpResponse)
	if err != nil {
		return false, err
	}

	if parsedResponse.StatusCode() != http.StatusOK {
		return false, fmt.Errorf("unexpected response status \"%d\"", parsedResponse.StatusCode())
	}

	stateDiscriminator, err := parsedResponse.ApplicationvndApiJSON200.Data.Attributes.Discriminator()
	if err != nil {
		return false, err
	}

	switch stateDiscriminator {
	case string(testModels.Accepted), string(testModels.InProgress):
		return false, nil
	case string(testModels.Completed):
		if _, err := parsedResponse.ApplicationvndApiJSON200.Data.Attributes.AsTestCompletedState(); err != nil {
			return false, err
		}
		return true, nil
	case string(testModels.Error):
		return false, parseTestError(parsedResponse, method)
	default:
		return false, fmt.Errorf("unexpected test status \"%s\"", stateDiscriminator)
	}
}

func (a *analysisOrchestrator) pollTestForDiscovery(ctx context.Context, client *testApi.Client, org uuid.UUID, testId openapi_types.UUID) (*sanitizers.Document, error) {
	if err := a.pollUntilTestComplete(ctx, client, org, testId, "Custom-sanitizer discovery timed out"); err != nil {
		return nil, err
	}
	findingsURL, err := a.discoveryFindingsURL(ctx, client, org, testId)
	if err != nil {
		return nil, err
	}
	return sanitizers.FetchDiscoveryDocument(ctx, a.httpClient, findingsURL)
}

func (a *analysisOrchestrator) discoveryFindingsURL(ctx context.Context, client *testApi.Client, org uuid.UUID, testId openapi_types.UUID) (string, error) {
	components, err := a.getTestComponents(ctx, client, org, testId)
	if err != nil {
		return "", err
	}
	for _, component := range components {
		attrs := component.Attributes
		if attrs.Type != string(testModels.SanitizerDiscovery) || !attrs.Success {
			continue
		}
		if attrs.FindingsDocumentType != nil &&
			*attrs.FindingsDocumentType == testModels.CustomSanitizerDiscoveryDocument &&
			attrs.FindingsDocumentPath != nil {
			return a.host(true) + *attrs.FindingsDocumentPath + "?version=" + testApi.DocumentApiVersion, nil
		}
	}
	return "", errors.New("no custom-sanitizer-discovery component found")
}

func (a *analysisOrchestrator) pollTestForFindings(ctx context.Context, client *testApi.Client, org uuid.UUID, testId openapi_types.UUID) (*sarif.SarifResponse, *scan.ResultMetaData, error) {
	if err := a.pollUntilTestComplete(ctx, client, org, testId, "Snyk Code analysis timed out"); err != nil {
		return nil, nil, err
	}

	resultMetaData, err := a.retrieveTestComponents(ctx, client, org, testId)
	if err != nil {
		return nil, nil, err
	}

	findings, err := a.retrieveFindings(ctx, testId, resultMetaData.FindingsUrl)
	if err != nil {
		return nil, nil, err
	}

	return findings, resultMetaData, nil
}

func parseTestError(parsedResponse *testApi.GetTestResultResponse, method string) error {
	errorResponse, stateErrorStateError := parsedResponse.ApplicationvndApiJSON200.Data.Attributes.AsTestErrorState()

	if stateErrorStateError != nil {
		return stateErrorStateError
	}

	if errorResponse.Errors == nil {
		return fmt.Errorf("%s: test error state has no errors", method)
	}

	var testError error
	for _, error := range *errorResponse.Errors {
		// since the error is only partially defined, we to create an existing generic error and fill it with the available information
		tmp := cli.NewGeneralCLIFailureError(error.Message)
		tmp.Level = "error"
		tmp.ErrorCode = error.ErrorCode
		tmp.Title = error.Title
		tmp.StatusCode = parsedResponse.StatusCode()
		tmp.Classification = error.Classification

		if error.InfoUrl != nil {
			tmp.Type = *error.InfoUrl
			tmp.Links = []string{}
		}
		testError = goerrors.Join(testError, tmp)
	}

	if testError == nil {
		testError = fmt.Errorf("%s: test error state has no errors", method)
	}
	return testError
}

func (a *analysisOrchestrator) getTestComponents(ctx context.Context, client *testApi.Client, org uuid.UUID, testId openapi_types.UUID) ([]testModels.GetComponentsResponseItem, error) {
	method := "analysis.getTestComponents"
	logger := a.logger.With().Str("method", method).Logger()
	logger.Debug().Msg("retrieving test components")

	httpResponse, err := client.GetComponents(
		ctx,
		org,
		testId,
		&testApi.GetComponentsParams{Version: testApi.ApiVersion},
	)
	if err != nil {
		logger.Err(err).Str("testId", testId.String()).Msg("error requesting the test components")
		return nil, err
	}

	defer func() {
		closeErr := httpResponse.Body.Close()
		if closeErr != nil {
			a.logger.Err(closeErr).Msg("failed to close response body")
		}
	}()

	parsedResponse, err := testApi.ParseGetComponentsResponse(httpResponse)
	if err != nil {
		return nil, err
	}

	if parsedResponse.ApplicationvndApiJSON200 == nil {
		return nil, fmt.Errorf("%s: unexpected response status \"%d\"", method, parsedResponse.StatusCode())
	}

	return parsedResponse.ApplicationvndApiJSON200.Data, nil
}

func (a *analysisOrchestrator) retrieveTestComponents(ctx context.Context, client *testApi.Client, org uuid.UUID, testId openapi_types.UUID) (*scan.ResultMetaData, error) {
	method := "analysis.retrieveTestComponents"
	data, err := a.getTestComponents(ctx, client, org, testId)
	if err != nil {
		return nil, err
	}

	var sastComponent *testModels.GetComponentsResponseItem
	for _, component := range data {
		if component.Attributes.Type == "sast" {
			a.logger.Trace().Msgf("inner component: %+v", component)
			sastComponent = &component
			break
		}
	}
	if sastComponent == nil {
		return nil, fmt.Errorf("%s: no sast component found", method)
	}

	result := &scan.ResultMetaData{}
	attributes := sastComponent.Attributes

	if !attributes.Success {
		return nil, fmt.Errorf("%s: sast scan did not complete successfully", method)
	}

	if attributes.FindingsDocumentType != nil && *attributes.FindingsDocumentType == testModels.Sarif {
		findingsUrl := a.host(true) + *attributes.FindingsDocumentPath + "?version=" + testApi.DocumentApiVersion
		result.FindingsUrl = findingsUrl

		if attributes.Webui != nil {
			if attributes.Webui.Link != nil {
				result.WebUiUrl = *attributes.Webui.Link
			}
			if attributes.Webui.ProjectId != nil {
				result.ProjectId = attributes.Webui.ProjectId.String()
			}
			if attributes.Webui.SnapshotId != nil {
				result.SnapshotId = attributes.Webui.SnapshotId.String()
			}
		}
	}
	return result, nil
}
