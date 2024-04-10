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
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/config"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/internal/util"
	workspaceClient "github.com/snyk/code-client-go/internal/workspace/2024-03-12"
	externalRef3 "github.com/snyk/code-client-go/internal/workspace/2024-03-12/workspaces"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/sarif"
)

//go:embed fake.json
var fakeResponse []byte

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
	RunAnalysis() (*sarif.SarifResponse, error)
}

func NewAnalysisOrchestrator(
	logger *zerolog.Logger,
	httpClient codeClientHTTP.HTTPClient,
	instrumentor observability.Instrumentor,
	errorReporter observability.ErrorReporter,
	config config.Config,
) *analysisOrchestrator {
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
	log := a.logger.With().Str("method", method).Logger()
	log.Debug().Msg("API: Creating the workspace")

	span := a.instrumentor.StartSpan(ctx, method)
	defer a.instrumentor.Finish(span)

	orgUUID := uuid.MustParse(orgId)

	repositoryUri, err := util.GetRepositoryUrl(path)
	if err != nil {
		a.errorReporter.CaptureError(err, observability.ErrorReporterOptions{ErrorDiagnosticPath: path})
		return "", fmt.Errorf("workspace is not a repository, cannot scan, %w", err)
	}

	a.logger.Info().Str("path", path).Str("repositoryUri", repositoryUri).Str("bundleHash", bundleHash).Msg("creating workspace")

	workspace, err := workspaceClient.NewClientWithResponses(fmt.Sprintf("%s/hidden", a.config.SnykApi()), workspaceClient.WithHTTPClient(a.httpClient))
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
				BundleId      string                                                       `json:"bundle_id"`
				RepositoryUri string                                                       `json:"repository_uri"`
				WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			} `json:"attributes"`
			Type externalRef3.WorkspacePostRequestDataType `json:"type"`
		}(struct {
			Attributes struct {
				BundleId      string                                                       `json:"bundle_id"`
				RepositoryUri string                                                       `json:"repository_uri"`
				WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			}
			Type externalRef3.WorkspacePostRequestDataType
		}{Attributes: struct {
			BundleId      string                                                       `json:"bundle_id"`
			RepositoryUri string                                                       `json:"repository_uri"`
			WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
		}(struct {
			BundleId      string
			RepositoryUri string
			WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType
		}{
			BundleId:      bundleHash,
			RepositoryUri: repositoryUri,
			WorkspaceType: "file_bundle_workspace",
		}),
			Type: "workspace",
		}),
	})
	if err != nil {
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

func (*analysisOrchestrator) RunAnalysis() (*sarif.SarifResponse, error) {
	var response sarif.SarifResponse

	err := json.Unmarshal(fakeResponse, &response)
	if err != nil {
		return nil, fmt.Errorf("failed to create SARIF response: %w", err)
	}
	return &response, nil
}
