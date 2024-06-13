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

	"github.com/snyk/code-client-go/config"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	orchestrationClient "github.com/snyk/code-client-go/internal/orchestration/2024-02-16"
	scans "github.com/snyk/code-client-go/internal/orchestration/2024-02-16/scans"
	workspaceClient "github.com/snyk/code-client-go/internal/workspace/2024-05-14"
	workspaces "github.com/snyk/code-client-go/internal/workspace/2024-05-14/workspaces"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
)

//go:generate mockgen -destination=mocks/analysis.go -source=analysis.go -package mocks
type AnalysisOrchestrator interface {
	CreateWorkspace(ctx context.Context, orgId string, requestId string, path scan.Target, bundleHash string) (string, error)
	RunAnalysis(ctx context.Context, orgId string, rootPath string, workspaceId string) (*sarif.SarifResponse, error)
	RunIncrementalAnalysis(ctx context.Context, orgId string, rootPath string, workspaceId string, limitToFiles []string) (*sarif.SarifResponse, error)
}

type analysisOrchestrator struct {
	httpClient       codeClientHTTP.HTTPClient
	instrumentor     observability.Instrumentor
	errorReporter    observability.ErrorReporter
	logger           *zerolog.Logger
	trackerFactory   scan.TrackerFactory
	config           config.Config
	timeoutInSeconds time.Duration
	flow             scans.Flow
}

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

func WithTimeoutInSeconds(timeoutInSeconds time.Duration) func(*analysisOrchestrator) {
	return func(a *analysisOrchestrator) {
		a.timeoutInSeconds = timeoutInSeconds
	}
}

func WithFlow(flow string) func(*analysisOrchestrator) {
	return func(a *analysisOrchestrator) {
		a.flow = scans.Flow{}
		_ = a.flow.UnmarshalJSON([]byte(fmt.Sprintf(`{"name": "%s"}`, flow)))
	}
}

func NewAnalysisOrchestrator(
	config config.Config,
	httpClient codeClientHTTP.HTTPClient,
	options ...OptionFunc,
) AnalysisOrchestrator {
	nopLogger := zerolog.Nop()
	flow := scans.Flow{}
	_ = flow.UnmarshalJSON([]byte(fmt.Sprintf(`{"name": "%s"}`, scans.IdeTest)))

	a := &analysisOrchestrator{
		httpClient:       httpClient,
		config:           config,
		instrumentor:     observability.NewInstrumentor(),
		trackerFactory:   scan.NewNoopTrackerFactory(),
		errorReporter:    observability.NewErrorReporter(&nopLogger),
		logger:           &nopLogger,
		timeoutInSeconds: 120 * time.Second,
		flow:             flow,
	}

	for _, option := range options {
		option(a)
	}

	return a
}

func (a *analysisOrchestrator) CreateWorkspace(ctx context.Context, orgId string, requestId string, target scan.Target, bundleHash string) (string, error) {
	method := "analysis.CreateWorkspace"
	logger := a.logger.With().Str("method", method).Logger()
	logger.Debug().Msg("API: Creating the workspace")

	span := a.instrumentor.StartSpan(ctx, method)
	defer a.instrumentor.Finish(span)

	tracker := a.trackerFactory.GenerateTracker()
	tracker.Begin("Creating file bundle workspace", "")
	defer tracker.End("")

	orgUUID := uuid.MustParse(orgId)

	if target == nil {
		return "", fmt.Errorf("target is nil")
	}

	repositoryTargetPath := target.GetPath()
	var repositoryTargetURL string
	if repositoryTarget, ok := target.(*scan.RepositoryTarget); ok {
		repositoryTargetPath, repositoryTargetURL = repositoryTarget.GetPath(), repositoryTarget.GetRepositoryUrl()
	}

	host := a.host(true)
	a.logger.Info().Str("host", host).Str("path", repositoryTargetPath).Str("repositoryUri", repositoryTargetURL).Msg("creating workspace")

	workspace, err := workspaceClient.NewClientWithResponses(host, workspaceClient.WithHTTPClient(a.httpClient))
	if err != nil {
		a.errorReporter.CaptureError(err, observability.ErrorReporterOptions{ErrorDiagnosticPath: repositoryTargetPath})
		return "", fmt.Errorf("failed to connect to the workspace API %w", err)
	}

	workspaceResponse, err := workspace.CreateWorkspaceWithApplicationVndAPIPlusJSONBodyWithResponse(ctx, orgUUID, &workspaceClient.CreateWorkspaceParams{
		Version:       "2024-05-14~experimental",
		SnykRequestId: uuid.MustParse(requestId),
		ContentType:   "application/vnd.api+json",
		UserAgent:     "cli",
	}, workspaceClient.CreateWorkspaceApplicationVndAPIPlusJSONRequestBody{
		Data: struct {
			Attributes struct {
				BundleId      string                                                     `json:"bundle_id"`
				RepositoryUri string                                                     `json:"repository_uri"`
				RootFolderId  string                                                     `json:"root_folder_id"`
				WorkspaceType workspaces.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			} `json:"attributes"`
			Type workspaces.WorkspacePostRequestDataType `json:"type"`
		}(struct {
			Attributes struct {
				BundleId      string                                                     `json:"bundle_id"`
				RepositoryUri string                                                     `json:"repository_uri"`
				RootFolderId  string                                                     `json:"root_folder_id"`
				WorkspaceType workspaces.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			}
			Type workspaces.WorkspacePostRequestDataType
		}{Attributes: struct {
			BundleId      string                                                     `json:"bundle_id"`
			RepositoryUri string                                                     `json:"repository_uri"`
			RootFolderId  string                                                     `json:"root_folder_id"`
			WorkspaceType workspaces.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
		}(struct {
			BundleId      string
			RepositoryUri string
			RootFolderId  string
			WorkspaceType workspaces.WorkspacePostRequestDataAttributesWorkspaceType
		}{
			BundleId:      bundleHash,
			RepositoryUri: repositoryTargetURL,
			WorkspaceType: "file_bundle_workspace",
			RootFolderId:  target.GetPath(),
		}),
			Type: "workspace",
		}),
	})
	if err != nil {
		a.logger.Error().Err(err).Msg("could not create workspace")
		return "", err
	}

	if workspaceResponse.ApplicationvndApiJSON201 == nil {
		var msg string
		switch workspaceResponse.StatusCode() {
		case 400:
			msg = workspaceResponse.ApplicationvndApiJSON400.Errors[0].Detail
		case 401:
			msg = workspaceResponse.ApplicationvndApiJSON401.Errors[0].Detail
		case 403:
			msg = workspaceResponse.ApplicationvndApiJSON403.Errors[0].Detail
		case 500:
			msg = workspaceResponse.ApplicationvndApiJSON500.Errors[0].Detail
		}
		return "", errors.New(msg)
	}

	workspaceId := workspaceResponse.ApplicationvndApiJSON201.Data.Id.String()
	a.logger.Debug().Str("workspaceId", workspaceId).Msg("finished creating workspace")
	return workspaceId, nil
}

func (a *analysisOrchestrator) RunAnalysis(ctx context.Context, orgId string, rootPath string, workspaceId string) (*sarif.SarifResponse, error) {
	return a.RunIncrementalAnalysis(ctx, orgId, rootPath, workspaceId, []string{})
}

func (a *analysisOrchestrator) RunIncrementalAnalysis(ctx context.Context, orgId string, rootPath string, workspaceId string, limitToFiles []string) (*sarif.SarifResponse, error) {
	method := "analysis.RunAnalysis"
	logger := a.logger.With().Str("method", method).Logger()
	logger.Debug().Msg("API: Creating the scan")

	tracker := a.trackerFactory.GenerateTracker()
	tracker.Begin("Snyk Code analysis for "+rootPath, "Retrieving results...")

	org := uuid.MustParse(orgId)

	host := a.host(false)
	a.logger.Debug().Str("host", host).Str("workspaceId", workspaceId).Interface("limitToFiles", limitToFiles).Msg("starting scan")

	client, err := orchestrationClient.NewClientWithResponses(host, orchestrationClient.WithHTTPClient(a.httpClient))
	if err != nil {
		tracker.End(fmt.Sprintf("Analysis failed: %v", err))
		return nil, fmt.Errorf("failed to create orchestrationClient: %w", err)
	}

	scanJobId, err := a.triggerScan(ctx, client, org, workspaceId, limitToFiles)
	if err != nil {
		tracker.End(fmt.Sprintf("Analysis failed: %v", err))
		return nil, err
	}

	response, err := a.pollScanForFindings(ctx, client, org, *scanJobId)
	if err != nil {
		tracker.End(fmt.Sprintf("Analysis failed: %v", err))
		return nil, err
	}

	tracker.End("Analysis complete.")
	return response, nil
}

func (a *analysisOrchestrator) triggerScan(
	ctx context.Context,
	client *orchestrationClient.ClientWithResponses,
	org uuid.UUID,
	workspaceId string,
	limitToFiles []string,
) (*openapi_types.UUID, error) {
	workspaceUUID := uuid.MustParse(workspaceId)

	scanOptions := &struct {
		LimitScanToFiles *[]string `json:"limit_scan_to_files,omitempty"`
	}{
		LimitScanToFiles: &limitToFiles,
	}

	if len(limitToFiles) == 0 {
		scanOptions = nil
	}

	data := struct {
		Attributes struct {
			Flow        scans.Flow `json:"flow"`
			ScanOptions *struct {
				LimitScanToFiles *[]string `json:"limit_scan_to_files,omitempty"`
			} `json:"scan_options,omitempty"`
			WorkspaceId  *openapi_types.UUID `json:"workspace_id,omitempty"`
			WorkspaceUrl string              `json:"workspace_url"`
		} `json:"attributes"`
		Id   *openapi_types.UUID           `json:"id,omitempty"`
		Type scans.PostScanRequestDataType `json:"type"`
	}{
		Attributes: struct {
			Flow        scans.Flow `json:"flow"`
			ScanOptions *struct {
				LimitScanToFiles *[]string `json:"limit_scan_to_files,omitempty"`
			} `json:"scan_options,omitempty"`
			WorkspaceId  *openapi_types.UUID `json:"workspace_id,omitempty"`
			WorkspaceUrl string              `json:"workspace_url"`
		}{
			Flow:         a.flow,
			WorkspaceUrl: fmt.Sprintf("http://workspace-service/workspaces/%s", workspaceId),
			WorkspaceId:  &workspaceUUID,
			ScanOptions:  scanOptions,
		},
		Type: "workspace",
	}

	createScanResponse, err := client.CreateScanWorkspaceJobForUserWithApplicationVndAPIPlusJSONBodyWithResponse(
		ctx,
		org,
		&orchestrationClient.CreateScanWorkspaceJobForUserParams{Version: "2024-02-16~experimental"},
		orchestrationClient.CreateScanWorkspaceJobForUserApplicationVndAPIPlusJSONRequestBody{Data: data})

	if err != nil {
		return nil, fmt.Errorf("failed to trigger scan: %w", err)
	}

	var scanJobId openapi_types.UUID
	var msg string
	switch createScanResponse.StatusCode() {
	case 201:
		scanJobId = createScanResponse.ApplicationvndApiJSON201.Data.Id
		a.logger.Debug().Str("workspaceId", workspaceId).Msg("starting scan")
	case 400:
		msg = createScanResponse.ApplicationvndApiJSON400.Errors[0].Detail
	case 401:
		msg = createScanResponse.ApplicationvndApiJSON401.Errors[0].Detail
	case 403:
		msg = createScanResponse.ApplicationvndApiJSON403.Errors[0].Detail
	case 404:
		msg = createScanResponse.ApplicationvndApiJSON404.Errors[0].Detail
	case 429:
		msg = createScanResponse.ApplicationvndApiJSON429.Errors[0].Detail
	case 500:
		msg = createScanResponse.ApplicationvndApiJSON500.Errors[0].Detail
	}
	if msg != "" {
		return nil, errors.New(msg)
	}

	return &scanJobId, nil
}

func (a *analysisOrchestrator) pollScanForFindings(ctx context.Context, client *orchestrationClient.ClientWithResponses, org uuid.UUID, scanJobId openapi_types.UUID) (*sarif.SarifResponse, error) {
	method := "analysis.pollScanForFindings"
	logger := a.logger.With().Str("method", method).Logger()

	pollingTicker := time.NewTicker(1 * time.Second)
	defer pollingTicker.Stop()
	timeoutTimer := time.NewTimer(a.timeoutInSeconds)
	defer timeoutTimer.Stop()
	for {
		select {
		case <-timeoutTimer.C:
			msg := "Snyk Code analysis timed out"
			logger.Error().Str("scanJobId", scanJobId.String()).Msg(msg)
			return nil, errors.New(msg)
		case <-pollingTicker.C:
			findingsUrl, complete, err := a.retrieveFindingsURL(ctx, client, org, scanJobId)
			if err != nil {
				return nil, err
			}
			if !complete {
				continue
			}

			findings, err := a.retrieveFindings(ctx, scanJobId, findingsUrl)
			if err != nil {
				return nil, err
			}

			return findings, nil
		}
	}
}

func (a *analysisOrchestrator) retrieveFindingsURL(ctx context.Context, client *orchestrationClient.ClientWithResponses, org uuid.UUID, scanJobId openapi_types.UUID) (string, bool, error) {
	method := "analysis.retrieveFindingsURL"
	logger := a.logger.With().Str("method", method).Logger()
	logger.Debug().Msg("retrieving findings URL")

	httpResponse, err := client.GetScanWorkspaceJobForUserWithResponse(
		ctx,
		org,
		scanJobId,
		&orchestrationClient.GetScanWorkspaceJobForUserParams{Version: "2024-02-16~experimental"},
	)
	if err != nil {
		logger.Err(err).Str("scanJobId", scanJobId.String()).Msg("error requesting the ScanJobResult")
		return "", true, err
	}

	var msg string
	switch httpResponse.StatusCode() {
	case 200:
		scanJobStatus := httpResponse.ApplicationvndApiJSON200.Data.Attributes.Status
		if scanJobStatus == scans.ScanJobResultsAttributesStatusInProgress {
			return "", false, nil
		} else {
			findingsUrl := ""

			if len(httpResponse.ApplicationvndApiJSON200.Data.Attributes.Components) > 0 && httpResponse.ApplicationvndApiJSON200.Data.Attributes.Components[0].FindingsUrl != nil {
				findingsUrl = *httpResponse.ApplicationvndApiJSON200.Data.Attributes.Components[0].FindingsUrl
			}
			return findingsUrl, true, nil
		}
	case 400:
		msg = httpResponse.ApplicationvndApiJSON400.Errors[0].Detail
	case 401:
		msg = httpResponse.ApplicationvndApiJSON401.Errors[0].Detail
	case 403:
		msg = httpResponse.ApplicationvndApiJSON403.Errors[0].Detail
	case 404:
		msg = httpResponse.ApplicationvndApiJSON404.Errors[0].Detail
	case 429:
		msg = httpResponse.ApplicationvndApiJSON429.Errors[0].Detail
	case 500:
		msg = httpResponse.ApplicationvndApiJSON500.Errors[0].Detail
	}
	return "", true, errors.New(msg)
}

func (a *analysisOrchestrator) retrieveFindings(ctx context.Context, scanJobId uuid.UUID, findingsUrl string) (*sarif.SarifResponse, error) {
	method := "analysis.retrieveFindings"
	logger := a.logger.With().Str("method", method).Logger()
	logger.Debug().Str("scanJobId", scanJobId.String()).Msg("retrieving findings from URL for scan job")

	if findingsUrl == "" {
		return nil, errors.New("do not have a findings URL")
	}
	req, err := http.NewRequest(http.MethodGet, findingsUrl, nil)
	req = req.WithContext(ctx)

	if err != nil {
		return nil, err
	}
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
