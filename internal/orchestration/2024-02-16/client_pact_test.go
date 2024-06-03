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

package v20240216_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	v20240216 "github.com/snyk/code-client-go/internal/orchestration/2024-02-16"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/pact-foundation/pact-go/dsl"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	codeClientHTTP "github.com/snyk/code-client-go/http"
	scans "github.com/snyk/code-client-go/internal/orchestration/2024-02-16/scans"
	"github.com/snyk/code-client-go/internal/util/testutil"
)

const (
	consumer     = "code-client-go"
	pactDir      = "./pacts"
	pactProvider = "OrchestrationApi"

	orgUUID     = "e7ea34c9-de0f-422c-bf2c-4654c2e2da90"
	workspaceId = "b6ea34c9-de0f-422c-bf2c-4654c2e2da90"
	uuidMatcher = "^.+[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

// Common test data
var pact dsl.Pact
var client *v20240216.ClientWithResponses

func TestOrchestrationClientPact(t *testing.T) {
	setupPact(t)
	defer pact.Teardown()

	defer func() {
		if err := pact.WritePact(); err != nil {
			t.Fatal(err)
		}
	}()

	// https://snyk.roadie.so/catalog/default/api/orchestration-service_2024-02-16_experimental
	t.Run("Create scan", func(t *testing.T) {
		pact.AddInteraction().Given("New scan").UponReceiving("Trigger scan").WithRequest(dsl.Request{
			Method: "POST",
			Path:   dsl.String(fmt.Sprintf("/orgs/%s/scans", orgUUID)),
			Query: dsl.MapMatcher{
				"version": dsl.String("2024-02-16~experimental"),
			},
			Headers: getHeaderMatcher(),
			Body:    getBodyMatcher(),
		}).WillRespondWith(dsl.Response{
			Status: 201,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/vnd.api+json"),
			},
			Body: dsl.Like(map[string]interface{}{
				"data": dsl.Like(map[string]interface{}{
					"attributes": dsl.Like(map[string]interface{}{
						"created_at": dsl.Timestamp(),
						"status":     dsl.String("success"),
					}),
					"type": dsl.String("workspace"),
				}),
			}),
		})

		flow := scans.Flow{}
		err := flow.UnmarshalJSON([]byte(`{"name": "cli_test"}`))
		require.NoError(t, err)

		test := func() error {
			_, err = client.CreateScanWorkspaceJobForUserWithApplicationVndAPIPlusJSONBodyWithResponse(
				context.Background(),
				uuid.MustParse(orgUUID),
				&v20240216.CreateScanWorkspaceJobForUserParams{
					Version: "2024-02-16~experimental",
				},
				v20240216.CreateScanWorkspaceJobForUserApplicationVndAPIPlusJSONRequestBody{
					Data: struct {
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
						Type: "cli",
					})})
			if err != nil {
				return err
			}
			return nil
		}

		err = pact.Verify(test)

		if err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
	})

	t.Run("Get scan", func(t *testing.T) {
		id := uuid.New()

		pact.AddInteraction().Given("Scan ID").UponReceiving("Retrieve scan").WithRequest(dsl.Request{
			Method: "GET",
			Path:   dsl.String(fmt.Sprintf("/orgs/%s/scans/%s", orgUUID, id.String())),
			Query: dsl.MapMatcher{
				"version": dsl.String("2024-02-16~experimental"),
			},
			Headers: dsl.MapMatcher{},
		}).WillRespondWith(dsl.Response{
			Status: 201,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			Body: dsl.Match(scans.ScanResultsResponse{}),
		})

		test := func() error {
			_, err := client.GetScanWorkspaceJobForUserWithResponse(
				context.Background(),
				uuid.MustParse(orgUUID),
				id,
				&v20240216.GetScanWorkspaceJobForUserParams{Version: "2024-02-16~experimental"})
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
	httpClient := codeClientHTTP.NewHTTPClient(
		func() *http.Client {
			return http.DefaultClient
		},
		codeClientHTTP.WithRetryCount(3),
		codeClientHTTP.WithInstrumentor(instrumentor),
		codeClientHTTP.WithErrorReporter(errorReporter),
		codeClientHTTP.WithLogger(&logger),
	)
	var err error
	client, err = v20240216.NewClientWithResponses(restApi, v20240216.WithHTTPClient(httpClient))
	require.NoError(t, err)
}

func getHeaderMatcher() dsl.MapMatcher {
	return dsl.MapMatcher{}
}

func getBodyMatcher() dsl.Matcher {
	return dsl.Like(map[string]interface{}{
		"data": dsl.Like(map[string]interface{}{
			"attributes": dsl.Like(map[string]interface{}{
				"flow": dsl.MapMatcher{
					"name": dsl.String("ide"),
				},
				"workspace_url": getWorkspaceIDMatcher(),
			}),
			"type": dsl.String("cli"),
		}),
	})
}

func getWorkspaceIDMatcher() dsl.Matcher {
	return dsl.Regex("http://workspace-service/workspaces/fc763eba-0905-41c5-a27f-3934ab26786c", uuidMatcher)
}
