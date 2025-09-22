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
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/config"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	testApi "github.com/snyk/code-client-go/internal/api/test/2025-04-07"
	testModels "github.com/snyk/code-client-go/internal/api/test/2025-04-07/models"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
)

//go:generate go tool github.com/golang/mock/mockgen -destination=mocks/analysis.go -source=analysis.go -package mocks

type AnalysisOrchestrator interface {
	RunTest(ctx context.Context, orgId string, b bundle.Bundle, target scan.Target, reportingOptions AnalysisConfig) (*sarif.SarifResponse, *scan.ResultMetaData, error)
	RunTestRemote(ctx context.Context, orgId string, reportingOptions AnalysisConfig) (*sarif.SarifResponse, *scan.ResultMetaData, error)
	RunLegacyTest(ctx context.Context, bundleHash string, shardKey string, limitToFiles []string, severity int) (*sarif.SarifResponse, scan.LegacyScanStatus, error)
}

type AnalysisConfig struct {
	Report          bool
	ProjectName     *string
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

func (a *analysisOrchestrator) createTestAndGetResults(ctx context.Context, orgId string, body *testApi.CreateTestApplicationVndAPIPlusJSONRequestBody, progressString string) (*sarif.SarifResponse, *scan.ResultMetaData, error) {
	tracker := a.trackerFactory.GenerateTracker()
	tracker.Begin(progressString, "Retrieving results...")

	innerFunction := func() (*sarif.SarifResponse, *scan.ResultMetaData, error) {
		params := testApi.CreateTestParams{Version: testApi.ApiVersion}
		orgUuid := uuid.MustParse(orgId)
		host := a.host(true)

		client, err := testApi.NewClient(host, testApi.WithHTTPClient(a.httpClient))
		if err != nil {
			return nil, nil, err
		}

		// create test
		resp, err := client.CreateTestWithApplicationVndAPIPlusJSONBody(ctx, orgUuid, &params, *body)
		if err != nil {
			return nil, nil, err
		}

		parsedResponse, err := testApi.ParseCreateTestResponse(resp)
		defer func() {
			closeErr := resp.Body.Close()
			if closeErr != nil {
				a.logger.Err(closeErr).Msg("failed to close response body")
			}
		}()
		if err != nil {
			a.logger.Debug().Msg(err.Error())
			return nil, nil, err
		}

		switch parsedResponse.StatusCode() {
		case http.StatusCreated:
			// poll results
			return a.pollTestForFindings(ctx, client, orgUuid, parsedResponse.ApplicationvndApiJSON201.Data.Id)
		}
		return nil, nil, nil
	}

	result, metadata, err := innerFunction()
	if err != nil {
		tracker.End("Analysis failed.")
	} else {
		tracker.End("Analysis completed.")
	}

	return result, metadata, err
}

func (a *analysisOrchestrator) RunTest(ctx context.Context, orgId string, b bundle.Bundle, target scan.Target, reportingConfig AnalysisConfig) (*sarif.SarifResponse, *scan.ResultMetaData, error) {
	var commitId *string = nil
	var repoUrl *string = nil
	if repoTarget, ok := target.(*scan.RepositoryTarget); ok {
		tmpRepoUrl := repoTarget.GetRepositoryUrl()
		if len(tmpRepoUrl) > 0 {
			repoUrl = &tmpRepoUrl
		}
		tmpCommitId := repoTarget.GetCommitId()
		if len(tmpCommitId) > 0 {
			commitId = &tmpCommitId
		}
	}

	body := testApi.NewCreateTestApplicationBody(
		testApi.WithInputBundle(b.GetBundleHash(), target.GetPath(), repoUrl, b.GetLimitToFiles(), commitId),
		testApi.WithScanType(a.testType),
		testApi.WithProjectName(reportingConfig.ProjectName),
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

func (a *analysisOrchestrator) pollTestForFindings(ctx context.Context, client *testApi.Client, org uuid.UUID, testId openapi_types.UUID) (*sarif.SarifResponse, *scan.ResultMetaData, error) {
	method := "analysis.pollTestForFindings"
	logger := a.logger.With().Str("method", method).Logger()

	pollingTicker := time.NewTicker(1 * time.Second)
	defer pollingTicker.Stop()
	timeoutTimer := time.NewTimer(a.config.SnykCodeAnalysisTimeout())
	defer timeoutTimer.Stop()
	for {
		select {
		case <-timeoutTimer.C:
			msg := "Snyk Code analysis timed out"
			logger.Error().Str("scanJobId", testId.String()).Msg(msg)
			return nil, nil, errors.New(msg)
		case <-pollingTicker.C:
			resultMetaData, complete, err := a.retrieveTestURL(ctx, client, org, testId)
			if err != nil {
				return nil, nil, err
			}
			if complete {
				findings, findingsErr := a.retrieveFindings(ctx, testId, resultMetaData.FindingsUrl)
				if findingsErr != nil {
					return nil, nil, findingsErr
				}
				return findings, resultMetaData, nil
			}
		}
	}
}

func (a *analysisOrchestrator) retrieveTestURL(ctx context.Context, client *testApi.Client, org uuid.UUID, testId openapi_types.UUID) (resultMetaData *scan.ResultMetaData, completed bool, err error) {
	method := "analysis.retrieveTestURL"
	logger := a.logger.With().Str("method", method).Logger()
	logger.Debug().Msg("retrieving Test URL")

	httpResponse, err := client.GetTestResult(
		ctx,
		org,
		testId,
		&testApi.GetTestResultParams{Version: testApi.ApiVersion},
	)
	if err != nil {
		logger.Err(err).Str("testId", testId.String()).Msg("error requesting the ScanJobResult")
		return nil, false, err
	}
	defer func() {
		closeErr := httpResponse.Body.Close()
		if closeErr != nil {
			a.logger.Err(closeErr).Msg("failed to close response body")
		}
	}()

	parsedResponse, err := testApi.ParseGetTestResultResponse(httpResponse)
	if err != nil {
		return nil, false, err
	}

	switch parsedResponse.StatusCode() {
	case 200:
		stateDiscriminator, stateError := parsedResponse.ApplicationvndApiJSON200.Data.Attributes.Discriminator()
		if stateError != nil {
			return nil, false, stateError
		}

		switch stateDiscriminator {
		case string(testModels.Accepted):
			fallthrough
		case string(testModels.InProgress):
			return nil, false, nil
		case string(testModels.Completed):
			_, stateCompleteError := parsedResponse.ApplicationvndApiJSON200.Data.Attributes.AsTestCompletedState()
			if stateCompleteError != nil {
				return nil, false, stateCompleteError
			}
			components, err := a.retrieveTestComponents(ctx, client, org, testId)
			if err != nil {
				return nil, false, err
			}

			return components, true, nil
		default:
			return nil, false, fmt.Errorf("unexpected test status \"%s\"", stateDiscriminator)
		}
	default:
		return nil, false, fmt.Errorf("unexpected response status \"%d\"", parsedResponse.StatusCode())
	}
}

func (a *analysisOrchestrator) retrieveTestComponents(ctx context.Context, client *testApi.Client, org uuid.UUID, testId openapi_types.UUID) (*scan.ResultMetaData, error) {
	method := "analysis.retrieveTestComponents"
	logger := a.logger.With().Str("method", method).Logger()
	logger.Debug().Msg("retrieving Test Components")

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
	data := parsedResponse.ApplicationvndApiJSON200.Data
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
