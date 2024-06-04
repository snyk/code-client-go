//go:build CONTRACT

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

	"github.com/google/uuid"
	"github.com/pact-foundation/pact-go/v2/consumer"
	"github.com/pact-foundation/pact-go/v2/matchers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	codeClientHTTP "github.com/snyk/code-client-go/http"
	v20240216 "github.com/snyk/code-client-go/internal/orchestration/2024-02-16"
	"github.com/snyk/code-client-go/internal/util/testutil"
	v20240514 "github.com/snyk/code-client-go/internal/workspace/2024-05-14"
	workspaces "github.com/snyk/code-client-go/internal/workspace/2024-05-14/workspaces"
)

const (
	consumerName = "code-client-go"
	pactDir      = "./pacts"
	pactProvider = "WorkspaceApi"

	orgUUID   = "e7ea34c9-de0f-422c-bf2c-4654c2e2da90"
	requestId = "b6ea34c9-de0f-422c-bf2c-4654c2e2da90"
	uuidRegex = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

// Common test data
var (
	pact       *consumer.V2HTTPMockProvider
	httpClient v20240216.HttpRequestDoer
)

func TestWorkspaceClientPact(t *testing.T) {
	setupPact(t)

	// https://snyk.roadie.so/catalog/default/api/workspace-service_2024-05-14_experimental
	t.Run("Create workspace", func(t *testing.T) {
		pact.AddInteraction().Given("New workspace").UponReceiving("Create workspace").WithCompleteRequest(consumer.Request{
			Method: "POST",
			Path:   matchers.String(fmt.Sprintf("/orgs/%s/workspaces", orgUUID)),
			Query: matchers.MapMatcher{
				"version": matchers.String("2024-05-14~experimental"),
			},
			Headers: getHeaderMatcher(),
			Body:    getBodyMatcher(),
		}).WithCompleteResponse(consumer.Response{
			Status: 200,
			Headers: matchers.MapMatcher{
				"Content-Type": matchers.String("application/vnd.api+json"),
			},
			Body: matchers.MatchV2(workspaces.WorkspacePostResponse{}),
		})

		test := func(config consumer.MockServerConfig) error {
			client, err := v20240514.NewClientWithResponses(fmt.Sprintf("http://localhost:%d", config.Port), v20240514.WithHTTPClient(httpClient))
			require.NoError(t, err)
			_, err = client.CreateWorkspaceWithApplicationVndAPIPlusJSONBodyWithResponse(
				context.Background(),
				uuid.MustParse(orgUUID),
				&v20240514.CreateWorkspaceParams{
					Version:       "2024-05-14~experimental",
					SnykRequestId: uuid.MustParse(requestId),
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

		if err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
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
			return http.DefaultClient
		},
		codeClientHTTP.WithRetryCount(3),
		codeClientHTTP.WithInstrumentor(instrumentor),
		codeClientHTTP.WithErrorReporter(errorReporter),
		codeClientHTTP.WithLogger(&logger),
	)
	require.NoError(t, err)
}

func getHeaderMatcher() matchers.MapMatcher {
	return matchers.MapMatcher{
		"Snyk-Request-Id": getSnykRequestIdMatcher(),
	}
}

func getSnykRequestIdMatcher() matchers.Matcher {
	return matchers.Regex("fc763eba-0905-41c5-a27f-3934ab26786c", uuidRegex)
}

func getBodyMatcher() matchers.Matcher {
	return matchers.Like(make([]byte, 1))
}
