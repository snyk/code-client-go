//go:build contract

/*
 * © 2022-2024 Snyk Limited
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

package v20240514_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pact-foundation/pact-go/v2/consumer"
	"github.com/pact-foundation/pact-go/v2/matchers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	codeClientHTTP "github.com/snyk/code-client-go/http"
	v20240216 "github.com/snyk/code-client-go/internal/orchestration/2024-02-16"
	"github.com/snyk/code-client-go/internal/util/testutil"
	v20240514 "github.com/snyk/code-client-go/internal/workspace/2024-05-14"
	v202405142 "github.com/snyk/code-client-go/internal/workspace/2024-05-14/common"
	externalRef1 "github.com/snyk/code-client-go/internal/workspace/2024-05-14/links"
	workspaces "github.com/snyk/code-client-go/internal/workspace/2024-05-14/workspaces"
)

const (
	consumerName = "code-client-go"
	pactDir      = "./pacts"
	pactProvider = "workspace-service"

	orgUUID             = "e7ea34c9-de0f-422c-bf2c-4654c2e2da90"
	requestId           = "b6ea34c9-de0f-422c-bf2c-4654c2e2da90"
	uuidRegex           = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
	sessionTokenMatcher = "^Bearer [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

// Common test data
var (
	pact       *consumer.V2HTTPMockProvider
	httpClient v20240216.HttpRequestDoer
)

type Data struct {
	Id   string `json:"id"`
	Type string `json:"type"`
}

func TestWorkspaceClientPact(t *testing.T) {
	setupPact(t)

	// https://snyk.roadie.so/catalog/default/api/workspace-service_2024-05-14_experimental
	t.Run("Create workspace", func(t *testing.T) {
		pact.AddInteraction().Given("New workspace").UponReceiving("Create workspace").WithCompleteRequest(consumer.Request{
			Method: "POST",
			Path:   matchers.String(fmt.Sprintf("/hidden/orgs/%s/workspaces", orgUUID)),
			Query: matchers.MapMatcher{
				"version": matchers.String("2024-05-14~experimental"),
			},
			Headers: getHeaderMatcher(),
			Body:    getBodyMatcher(),
		}).WithCompleteResponse(consumer.Response{
			Status: 201,
			Headers: matchers.MapMatcher{
				"Content-Type": matchers.String("application/vnd.api+json; charset=utf-8"),
			}, Body: map[string]interface{}{
				"data": matchers.Like(Data{
					Id:   "9c2c14da-7035-4280-bafb-d3e874ebd4af",
					Type: "file_bundle_workspace",
				}),
				"jsonapi": matchers.MatchV2(&v202405142.JsonApi{}),
				"links":   matchers.MatchV2(&externalRef1.LinkSelf{}),
			},
			//  matchers.MatchV2(workspaces.WorkspacePostResponse{}), // not working due to uuid deserialisation https://github.com/pact-foundation/pact-go/issues/179
		})

		test := func(config consumer.MockServerConfig) error {
			client, err := v20240514.NewClientWithResponses(fmt.Sprintf("http://localhost:%d/hidden", config.Port), v20240514.WithHTTPClient(httpClient))
			if err != nil {
				return err
			}
			_, err = client.CreateWorkspaceWithApplicationVndAPIPlusJSONBodyWithResponse(
				context.Background(),
				uuid.MustParse(orgUUID),
				&v20240514.CreateWorkspaceParams{
					Version:       "2024-05-14~experimental",
					SnykRequestId: uuid.MustParse(requestId),
					UserAgent:     "code-client-go",
					ContentType:   "application/vnd.api+json",
				},
				v20240514.CreateWorkspaceApplicationVndAPIPlusJSONRequestBody{
					Data: struct {
						Attributes struct {
							BundleId      string                                                     `json:"bundle_id"`
							RepositoryUri string                                                     `json:"repository_uri"`
							RootFolderId  string                                                     `json:"root_folder_id"`
							WorkspaceType workspaces.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
						} `json:"attributes"`
						Type workspaces.WorkspacePostRequestDataType `json:"type"`
					}{
						Attributes: struct {
							BundleId      string                                                     `json:"bundle_id"`
							RepositoryUri string                                                     `json:"repository_uri"`
							RootFolderId  string                                                     `json:"root_folder_id"`
							WorkspaceType workspaces.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
						}{
							BundleId:      "YnVuZGxlSWQK",
							RepositoryUri: "https://github.com/snyk/code-client-go.git",
							RootFolderId:  "testFolder",
							WorkspaceType: "file_bundle_workspace",
						},
						Type: "workspace",
					},
				})
			if err != nil {
				return err
			}
			return nil
		}

		err := pact.ExecuteTest(t, test)
		require.NoError(t, err)
	})
}

func setupPact(t *testing.T) {
	t.Helper()

	config := consumer.MockHTTPProviderConfig{
		Consumer: consumerName,
		Provider: pactProvider,
		PactDir:  pactDir,
	}
	var err error
	pact, err = consumer.NewV2Pact(config)

	logger := zerolog.New(zerolog.NewTestWriter(t))
	instrumentor := testutil.NewTestInstrumentor()
	errorReporter := testutil.NewTestErrorReporter()
	httpClient = codeClientHTTP.NewHTTPClient(
		func() *http.Client {
			client := http.Client{
				Timeout:   time.Duration(60) * time.Second,
				Transport: testutil.TestAuthRoundTripper{http.DefaultTransport},
			}
			return &client
		},
		codeClientHTTP.WithRetryCount(1),
		codeClientHTTP.WithInstrumentor(instrumentor),
		codeClientHTTP.WithErrorReporter(errorReporter),
		codeClientHTTP.WithLogger(&logger),
	)
	require.NoError(t, err)
}

func getHeaderMatcher() matchers.MapMatcher {
	return matchers.MapMatcher{
		"Snyk-Request-Id": getSnykRequestIdMatcher(),
		"Content-Type":    matchers.S("application/vnd.api+json"),
		"User-Agent":      matchers.Regex("go-http-client/1.1", ".*"),
		"Authorization":   matchers.Regex("Bearer fc763eba-0905-41c5-a27f-3934ab26786c", sessionTokenMatcher),
	}
}

func getSnykRequestIdMatcher() matchers.Matcher {
	return matchers.Regex("fc763eba-0905-41c5-a27f-3934ab26786c", uuidRegex)
}

func getBodyMatcher() matchers.Matcher {
	return matchers.Like(v20240514.CreateWorkspaceApplicationVndAPIPlusJSONRequestBody{
		Data: struct {
			Attributes struct {
				BundleId      string                                                     `json:"bundle_id"`
				RepositoryUri string                                                     `json:"repository_uri"`
				RootFolderId  string                                                     `json:"root_folder_id"`
				WorkspaceType workspaces.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			} `json:"attributes"`
			Type workspaces.WorkspacePostRequestDataType `json:"type"`
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
			BundleId:      "sampleYnVuZGxlSWQK",
			RepositoryUri: "https://url.invalid/code-client-go.git",
			WorkspaceType: "file_bundle_workspace",
		}),
			Type: "workspace",
		},
	})
}
