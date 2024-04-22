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
	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/config"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	orchestrationClient "github.com/snyk/code-client-go/internal/orchestration/2024-02-16"
	scans "github.com/snyk/code-client-go/internal/orchestration/2024-02-16/scans"
	"github.com/snyk/code-client-go/internal/util"
	workspaceClient "github.com/snyk/code-client-go/internal/workspace/2024-03-12"
	workspaces "github.com/snyk/code-client-go/internal/workspace/2024-03-12/workspaces"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/sarif"

	"strings"
	"time"
)

type analysisOrchestrator struct {
	httpClient    codeClientHTTP.HTTPClient
	instrumentor  observability.Instrumentor
	errorReporter observability.ErrorReporter
	logger        *zerolog.Logger
	config        config.Config
}

//go:generate mockgen -destination=mocks/analysis.go -source=analysis.go -package mocks
type AnalysisOrchestrator interface {
	CreateWorkspace(ctx context.Context, orgId string, requestId string, path string, bundleHash string) (string, error)
	RunAnalysis(ctx context.Context, orgId string, workspaceId string) (*sarif.SarifResponse, error)
}

func NewAnalysisOrchestrator(
	config config.Config,
	logger *zerolog.Logger,
	httpClient codeClientHTTP.HTTPClient,
	instrumentor observability.Instrumentor,
	errorReporter observability.ErrorReporter,
) AnalysisOrchestrator {
	return &analysisOrchestrator{
		httpClient,
		instrumentor,
		errorReporter,
		logger,
		config,
	}
}

func (a *analysisOrchestrator) CreateWorkspace(ctx context.Context, orgId string, requestId string, path string, bundleHash string) (string, error) {
	method := "analysis.CreateWorkspace"
	logger := a.logger.With().Str("method", method).Logger()
	logger.Debug().Msg("API: Creating the workspace")

	span := a.instrumentor.StartSpan(ctx, method)
	defer a.instrumentor.Finish(span)

	orgUUID := uuid.MustParse(orgId)

	repositoryUri, err := util.GetRepositoryUrl(path)
	if err != nil {
		a.errorReporter.CaptureError(err, observability.ErrorReporterOptions{ErrorDiagnosticPath: path})
		return "", fmt.Errorf("workspace is not a repository, cannot scan, %w", err)
	}

	host := a.host()
	a.logger.Info().Str("host", host).Str("path", path).Str("repositoryUri", repositoryUri).Msg("creating workspace")

	workspace, err := workspaceClient.NewClientWithResponses(host, workspaceClient.WithHTTPClient(a.httpClient))
	if err != nil {
		a.errorReporter.CaptureError(err, observability.ErrorReporterOptions{ErrorDiagnosticPath: path})
		return "", fmt.Errorf("failed to connect to the workspace API %w", err)
	}

	workspaceResponse, err := workspace.CreateWorkspaceWithApplicationVndAPIPlusJSONBodyWithResponse(ctx, orgUUID, &workspaceClient.CreateWorkspaceParams{
		Version:       "2024-03-12~experimental",
		SnykRequestId: uuid.MustParse(requestId),
		ContentType:   "application/vnd.api+json",
		UserAgent:     "cli",
	}, workspaceClient.CreateWorkspaceApplicationVndAPIPlusJSONRequestBody{
		Data: struct {
			Attributes struct {
				BundleId      string                                                     `json:"bundle_id"`
				RepositoryUri string                                                     `json:"repository_uri"`
				WorkspaceType workspaces.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			} `json:"attributes"`
			Type workspaces.WorkspacePostRequestDataType `json:"type"`
		}(struct {
			Attributes struct {
				BundleId      string                                                     `json:"bundle_id"`
				RepositoryUri string                                                     `json:"repository_uri"`
				WorkspaceType workspaces.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			}
			Type workspaces.WorkspacePostRequestDataType
		}{Attributes: struct {
			BundleId      string                                                     `json:"bundle_id"`
			RepositoryUri string                                                     `json:"repository_uri"`
			WorkspaceType workspaces.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
		}(struct {
			BundleId      string
			RepositoryUri string
			WorkspaceType workspaces.WorkspacePostRequestDataAttributesWorkspaceType
		}{
			BundleId:      bundleHash,
			RepositoryUri: repositoryUri,
			WorkspaceType: "file_bundle_workspace",
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

	return workspaceResponse.ApplicationvndApiJSON201.Data.Id.String(), nil
}

//go:embed fake.json
var fakeResponse []byte

func (a *analysisOrchestrator) RunAnalysis(ctx context.Context, orgId string, workspaceId string) (*sarif.SarifResponse, error) {
	method := "analysis.RunAnalysis"
	logger := a.logger.With().Str("method", method).Logger()
	logger.Debug().Msg("API: Creating the scan")
	org := uuid.MustParse(orgId)

	host := fmt.Sprintf("%s/rest", a.config.SnykApi())
	a.logger.Debug().Str("host", host).Str("workspaceId", workspaceId).Msg("starting scan")

	client, err := orchestrationClient.NewClientWithResponses(host, orchestrationClient.WithHTTPClient(a.httpClient))
	if err != nil {
		return nil, fmt.Errorf("failed to create orchestrationClient: %w", err)
	}

	flow := scans.Flow{}
	err = flow.UnmarshalJSON([]byte(`{"name": "cli_test"}`))
	if err != nil {
		return nil, fmt.Errorf("failed to create scan request: %w", err)
	}
	createScanResponse, err := client.CreateScanWorkspaceJobForUserWithApplicationVndAPIPlusJSONBodyWithResponse(
		context.Background(),
		org,
		&orchestrationClient.CreateScanWorkspaceJobForUserParams{Version: "2024-02-16~experimental"},
		orchestrationClient.CreateScanWorkspaceJobForUserApplicationVndAPIPlusJSONRequestBody{Data: struct {
			Attributes struct {
				Flow         scans.Flow `json:"flow"`
				WorkspaceUrl string     `json:"workspace_url"`
			} `json:"attributes"`
			Id   *openapi_types.UUID           `json:"id,omitempty"`
			Type scans.PostScanRequestDataType `json:"type"`
		}(struct {
			Attributes struct {
				Flow         scans.Flow `json:"flow"`
				WorkspaceUrl string     `json:"workspace_url"`
			}
			Id   *openapi_types.UUID
			Type scans.PostScanRequestDataType
		}{
			Attributes: struct {
				Flow         scans.Flow `json:"flow"`
				WorkspaceUrl string     `json:"workspace_url"`
			}(struct {
				Flow         scans.Flow
				WorkspaceUrl string
			}{
				Flow:         flow,
				WorkspaceUrl: fmt.Sprintf("http://workspace-service/workspaces/%s", workspaceId),
			}),
			Type: "workspace",
		})})

	if err != nil {
		return nil, fmt.Errorf("failed to trigger scan: %w", err)
	}

	if createScanResponse.ApplicationvndApiJSON201 == nil {
		var msg string
		switch createScanResponse.StatusCode() {
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
		return nil, errors.New(msg)
	}

	scanJobId := createScanResponse.ApplicationvndApiJSON201.Data.Id
	a.logger.Debug().Str("host", host).Str("scanJobId", scanJobId.String()).Msg("starting scan")

	// Actual polling loop.
	pollingTicker := time.NewTicker(1 * time.Second)
	defer pollingTicker.Stop()
	timeoutTimer := time.NewTimer(2 * time.Minute)
	defer timeoutTimer.Stop()
	for {
		select {
		case <-timeoutTimer.C:
			msg := "timeout requesting the ScanJobResult"
			logger.Error().Str("scanJobId", scanJobId.String()).Msg(msg)
			return nil, errors.New(msg)

		case <-pollingTicker.C:
			_, complete, err := a.poller(logger, client, org, scanJobId, method) // todo add processing of the response with the findings
			if err != nil {
				return nil, err
			}
			if !complete {
				continue
			}

			var response sarif.SarifResponse
			_ = json.Unmarshal(fakeResponse, &response)

			return &response, nil
		}
	}
}

func (a *analysisOrchestrator) poller(logger zerolog.Logger, client *orchestrationClient.ClientWithResponses, org uuid.UUID, scanJobId openapi_types.UUID, method string) (response *orchestrationClient.GetScanWorkspaceJobForUserResponse, complete bool, err error) {
	logger.Debug().Msg("polling for ScanJobResult")
	httpResponse, err := client.GetScanWorkspaceJobForUserWithResponse(
		context.Background(),
		org,
		scanJobId,
		&orchestrationClient.GetScanWorkspaceJobForUserParams{Version: "2024-02-16~experimental"},
	)
	if err != nil {
		logger.Err(err).Str("method", method).Str("scanJobId", scanJobId.String()).Msg("error requesting the ScanJobResult")
		return httpResponse, true, err
	}

	scanJobStatus := httpResponse.ApplicationvndApiJSON200.Data.Attributes.Status
	if scanJobStatus == scans.ScanJobResultsAttributesStatusDone {
		return httpResponse, true, nil
	} else {
		var msg string
		switch httpResponse.StatusCode() {
		case 200: //Analysis still in progress.
			return httpResponse, false, nil
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
		return httpResponse, true, errors.New(msg)
	}
}

func (a *analysisOrchestrator) host() string {
	apiUrl := strings.TrimRight(a.config.SnykApi(), "/")
	return fmt.Sprintf("%s/hidden", apiUrl)
}
