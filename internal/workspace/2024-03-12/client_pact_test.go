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

package v20240312_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/pact-foundation/pact-go/dsl"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/internal/util/testutil"
	v20240312 "github.com/snyk/code-client-go/internal/workspace/2024-03-12"
	externalRef3 "github.com/snyk/code-client-go/internal/workspace/2024-03-12/workspaces"
)

const (
	consumer     = "code-client-go"
	pactDir      = "./pacts"
	pactProvider = "WorkspaceApi"

	orgUUID     = "e7ea34c9-de0f-422c-bf2c-4654c2e2da90"
	requestId   = "b6ea34c9-de0f-422c-bf2c-4654c2e2da90"
	uuidMatcher = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

// Common test data
var pact dsl.Pact
var client *v20240312.ClientWithResponses

func TestWorkspaceClientPact(t *testing.T) {
	setupPact(t)
	defer pact.Teardown()

	defer func() {
		if err := pact.WritePact(); err != nil {
			t.Fatal(err)
		}
	}()

	// https://snyk.roadie.so/catalog/default/api/workspace-service_2024-03-12_experimental
	t.Run("Create workspace", func(t *testing.T) {
		pact.AddInteraction().Given("New workspace").UponReceiving("Create workspace").WithRequest(dsl.Request{
			Method: "POST",
			Path:   dsl.String(fmt.Sprintf("/orgs/%s/workspaces", orgUUID)),
			Query: dsl.MapMatcher{
				"version": dsl.String("2024-03-12~experimental"),
			},
			Headers: getHeaderMatcher(),
			Body:    getBodyMatcher(),
		}).WillRespondWith(dsl.Response{
			Status: 200,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			Body: dsl.Match(externalRef3.WorkspacePostResponse{}),
		})

		test := func() error {
			_, err := client.CreateWorkspaceWithApplicationVndAPIPlusJSONBodyWithResponse(context.Background(), uuid.MustParse(orgUUID), &v20240312.CreateWorkspaceParams{
				Version:       "2024-03-12~experimental",
				SnykRequestId: uuid.MustParse(requestId),
			}, v20240312.CreateWorkspaceApplicationVndAPIPlusJSONRequestBody{
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
				}{BundleId: "YnVuZGxlSWQK", RepositoryUri: "https://github.com/snyk/code-client-go.git", WorkspaceType: "file_bundle_workspace"}), Type: "workspace"}),
			})
			if err != nil {
				return err
			}
			return nil
		}

		err := pact.Verify(test)

		if err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
	})
}

func setupPact(t *testing.T) {
	t.Helper()

	// Proactively start service to get access to the port
	pact = dsl.Pact{
		Consumer: consumer,
		Provider: pactProvider,
		PactDir:  pactDir,
	}

	pact.Setup(true)

	restApi := fmt.Sprintf("http://localhost:%d", pact.Server.Port)

	logger := zerolog.New(zerolog.NewTestWriter(t))
	instrumentor := testutil.NewTestInstrumentor()
	errorReporter := testutil.NewTestErrorReporter()
	httpClient := codeClientHTTP.NewHTTPClient(&logger, func() *http.Client {
		return http.DefaultClient
	}, instrumentor, errorReporter)
	var err error
	client, err = v20240312.NewClientWithResponses(restApi, v20240312.WithHTTPClient(httpClient))
	require.NoError(t, err)
}

func getHeaderMatcher() dsl.MapMatcher {
	return dsl.MapMatcher{
		"Snyk-Request-Id": getSnykRequestIdMatcher(),
	}
}

func getSnykRequestIdMatcher() dsl.Matcher {
	return dsl.Regex("fc763eba-0905-41c5-a27f-3934ab26786c", uuidMatcher)
}

func getBodyMatcher() dsl.Matcher {
	return dsl.Like(make([]byte, 1))
}
