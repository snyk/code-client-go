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
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"

	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/config"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	testApi "github.com/snyk/code-client-go/internal/api/test/2024-12-21"
	testModels "github.com/snyk/code-client-go/internal/api/test/2024-12-21/models"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
)

//go:generate mockgen -destination=mocks/analysis.go -source=analysis.go -package mocks
type AnalysisOrchestrator interface {
	RunTest(ctx context.Context, orgId string, b bundle.Bundle, target scan.Target, reportingOptions AnalysisConfig) (*sarif.SarifResponse, *scan.ResultMetaData, error)
	RunTestRemote(ctx context.Context, orgId string, reportingOptions AnalysisConfig) (*sarif.SarifResponse, *scan.ResultMetaData, error)
	RunLegacyTest(ctx context.Context, bundleHash string, shardKey string, limitToFiles []string, severity int) (*sarif.SarifResponse, LegacyAnalysisStatus, error)
}

type AnalysisConfig struct {
	Report          bool
	ProjectName     *string
	TargetName      *string
	TargetReference *string
	ProjectId       *uuid.UUID
	CommitId        *string
}

// Legacy analysis types and constants
const (
	legacyCompleteStatus = "COMPLETE"
)

type LegacyAnalysisStatus struct {
	Message    string
	Percentage int
}

type LegacyAnalysisRequestKey struct {
	Type         string   `json:"type"`
	Hash         string   `json:"hash"`
	LimitToFiles []string `json:"limitToFiles,omitempty"`
	Shard        string   `json:"shard"`
}

type legacyCodeRequestContextOrg struct {
	Name        string          `json:"name"`
	DisplayName string          `json:"displayName"`
	PublicId    string          `json:"publicId"`
	Flags       map[string]bool `json:"flags"`
}

type legacyCodeRequestContext struct {
	Initiator string                      `json:"initiator"`
	Flow      string                      `json:"flow,omitempty"`
	Org       legacyCodeRequestContextOrg `json:"org,omitempty"`
}

type LegacyAnalysisRequest struct {
	Key             LegacyAnalysisRequestKey `json:"key"`
	Severity        int                      `json:"severity,omitempty"`
	Prioritized     bool                     `json:"prioritized,omitempty"`
	Legacy          bool                     `json:"legacy"`
	AnalysisContext legacyCodeRequestContext `json:"analysisContext"`
}

type LegacyAnalysisFailedError struct {
	Msg string
}

func (e LegacyAnalysisFailedError) Error() string { return e.Msg }

type analysisOrchestrator struct {
	httpClient     codeClientHTTP.HTTPClient
	instrumentor   observability.Instrumentor
	errorReporter  observability.ErrorReporter
	logger         *zerolog.Logger
	trackerFactory scan.TrackerFactory
	config         config.Config
	testType       testModels.Scan
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

func WithResultType(t testModels.Scan) func(*analysisOrchestrator) {
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
	var repoUrl *string = nil
	if repoTarget, ok := target.(*scan.RepositoryTarget); ok {
		tmp := repoTarget.GetRepositoryUrl()
		repoUrl = &tmp
	}

	body := testApi.NewCreateTestApplicationBody(
		testApi.WithInputBundle(b.GetBundleHash(), target.GetPath(), repoUrl, b.GetLimitToFiles()),
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
		case string(testModels.TestAcceptedStateStatusAccepted):
			fallthrough
		case string(testModels.TestInProgressStateStatusInProgress):
			return nil, false, nil
		case string(testModels.TestCompletedStateStatusCompleted):
			testCompleted, stateCompleteError := parsedResponse.ApplicationvndApiJSON200.Data.Attributes.AsTestCompletedState()
			if stateCompleteError != nil {
				return nil, false, stateCompleteError
			}

			findingsUrl := a.host(true) + testCompleted.Documents.EnrichedSarif + "?version=" + testApi.DocumentApiVersion
			result := &scan.ResultMetaData{
				FindingsUrl: findingsUrl,
			}
			if testCompleted.Results.Webui != nil && testCompleted.Results.Webui.Link != nil {
				result.WebUiUrl = *testCompleted.Results.Webui.Link
			}
			return result, true, nil
		default:
			return nil, false, fmt.Errorf("unexpected test status \"%s\"", stateDiscriminator)
		}
	default:
		return nil, false, fmt.Errorf("unexpected response status \"%d\"", parsedResponse.StatusCode())
	}
}

// Legacy analysis helper functions
func (a *analysisOrchestrator) newLegacyCodeRequestContext() legacyCodeRequestContext {
	unknown := "unknown"
	orgId := unknown
	if a.config.Organization() != "" {
		orgId = a.config.Organization()
	}

	// TODO - needs to be dynamically generated
	return legacyCodeRequestContext{
		Initiator: "IDE",
		Flow:      "language-server",
		Org: legacyCodeRequestContextOrg{
			Name:        unknown,
			DisplayName: unknown,
			PublicId:    orgId,
		},
	}
}

func (a *analysisOrchestrator) createLegacyAnalysisRequestBody(bundleHash, shardKey string, limitToFiles []string, severity int) ([]byte, error) {
	request := LegacyAnalysisRequest{
		Key: LegacyAnalysisRequestKey{
			Type:         "file",
			Hash:         bundleHash,
			LimitToFiles: limitToFiles,
		},
		Legacy:          false,
		AnalysisContext: a.newLegacyCodeRequestContext(),
	}
	if len(shardKey) > 0 {
		request.Key.Shard = shardKey
	}
	if severity > 0 {
		request.Severity = severity
	}

	requestBody, err := json.Marshal(request)
	return requestBody, err
}

func (a *analysisOrchestrator) getLegacyCodeApiUrl() (string, error) {
	// Use the same logic as the original SnykCodeHTTPClient
	if !a.config.IsFedramp() {
		return a.config.SnykCodeApi(), nil
	}
	u, err := url.Parse(a.config.SnykCodeApi())
	if err != nil {
		return "", err
	}

	// Apply fedramp transformation (this might need adjustment based on the actual requirements)
	u.Host = strings.Replace(u.Host, "deeproxy", "api", 1)

	if a.config.Organization() == "" {
		return "", errors.New("Organization is required in a fedramp environment")
	}

	u.Path = "/hidden/orgs/" + a.config.Organization() + "/code"
	return u.String(), nil
}

func (a *analysisOrchestrator) logLegacySarifResponse(method string, sarifResponse sarif.SarifResponse) {
	a.logger.Debug().
		Str("method", method).
		Str("status", sarifResponse.Status).
		Float64("progress", sarifResponse.Progress).
		Int("fetchingCodeTime", sarifResponse.Timing.FetchingCode).
		Int("analysisTime", sarifResponse.Timing.Analysis).
		Int("filesAnalyzed", len(sarifResponse.Coverage)).
		Msg("Received response summary")
}

func (a *analysisOrchestrator) RunLegacyTest(ctx context.Context, bundleHash string, shardKey string, limitToFiles []string, severity int) (*sarif.SarifResponse, LegacyAnalysisStatus, error) {
	method := "analysis.RunLegacyTest"
	span := a.instrumentor.StartSpan(ctx, method)
	defer a.instrumentor.Finish(span)

	a.logger.Debug().Str("method", method).Str("bundleHash", bundleHash).Msg("API: Retrieving legacy analysis for bundle")
	defer a.logger.Debug().Str("method", method).Str("bundleHash", bundleHash).Msg("API: Retrieving legacy analysis done")

	requestBody, err := a.createLegacyAnalysisRequestBody(bundleHash, shardKey, limitToFiles, severity)
	if err != nil {
		a.logger.Err(err).Str("method", method).Str("requestBody", string(requestBody)).Msg("error creating request body")
		return nil, LegacyAnalysisStatus{}, err
	}

	// Get the legacy code API URL
	baseUrl, err := a.getLegacyCodeApiUrl()
	if err != nil {
		return nil, LegacyAnalysisStatus{}, err
	}

	// Create HTTP request
	analysisUrl := baseUrl + "/analysis"
	req, err := http.NewRequestWithContext(span.Context(), http.MethodPost, analysisUrl, bytes.NewBuffer(requestBody))
	if err != nil {
		a.logger.Err(err).Str("method", method).Msg("error creating HTTP request")
		return nil, LegacyAnalysisStatus{}, err
	}
	codeClientHTTP.AddDefaultHeaders(req, span.GetTraceId(), a.config.Organization())

	// Make HTTP call
	resp, err := a.httpClient.Do(req)
	failed := LegacyAnalysisStatus{Message: "FAILED"}
	if err != nil {
		a.logger.Err(err).Str("method", method).Msg("error response from analysis")
		return nil, failed, err
	}
	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			a.logger.Err(closeErr).Msg("failed to close response body")
		}
	}()

	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		a.logger.Err(err).Str("method", method).Msg("error reading response body")
		return nil, failed, err
	}

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		a.logger.Err(err).Str("method", method).Str("responseBody", string(responseBody)).Int("statusCode", resp.StatusCode).Msg("error response from analysis")
		return nil, failed, LegacyAnalysisFailedError{Msg: string(responseBody)}
	}

	var response sarif.SarifResponse
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		a.logger.Err(err).Str("method", method).Str("responseBody", string(responseBody)).Msg("error unmarshalling")
		return nil, failed, err
	} else {
		a.logLegacySarifResponse(method, response)
	}

	a.logger.Debug().Str("method", method).Str("bundleHash", bundleHash).Float64("progress",
		response.Progress).Msgf("Status: %s", response.Status)

	if response.Status == failed.Message {
		a.logger.Err(err).Str("method", method).Str("responseStatus", response.Status).Msg("analysis failed")
		return nil, failed, LegacyAnalysisFailedError{Msg: string(responseBody)}
	}

	if response.Status == "" {
		a.logger.Err(err).Str("method", method).Str("responseStatus", response.Status).Msg("unknown response status (empty)")
		return nil, failed, LegacyAnalysisFailedError{Msg: string(responseBody)}
	}

	status := LegacyAnalysisStatus{Message: response.Status, Percentage: int(math.RoundToEven(response.Progress * 100))}
	if response.Status != legacyCompleteStatus {
		return nil, status, nil
	}

	return &response, status, nil
}
