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

	"github.com/pact-foundation/pact-go/v2/consumer"
	"github.com/pact-foundation/pact-go/v2/matchers"

	v20240216 "github.com/snyk/code-client-go/internal/orchestration/2024-02-16"

	"github.com/google/uuid"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	codeClientHTTP "github.com/snyk/code-client-go/http"
	scans "github.com/snyk/code-client-go/internal/orchestration/2024-02-16/scans"
	"github.com/snyk/code-client-go/internal/util/testutil"
)

const (
	consumerName = "code-client-go"
	pactDir      = "./pacts"
	pactProvider = "OrchestrationApi"

	orgUUID       = "e7ea34c9-de0f-422c-bf2c-4654c2e2da90"
	workspaceId   = "b6ea34c9-de0f-422c-bf2c-4654c2e2da90"
	uuidRegex     = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
	uuidTailRegex = "^.+" + uuidRegex
)

var (
	workspaceUUID = uuid.MustParse(workspaceId)
	scanOptions   *struct {
		LimitScanToFiles *[]string `json:"limit_scan_to_files,omitempty"`
	}
	scanOptionsIncrementalScan = &struct {
		LimitScanToFiles *[]string `json:"limit_scan_to_files,omitempty"`
	}{
		LimitScanToFiles: &[]string{"fileA", "fileB"},
	}

	pact       *consumer.V2HTTPMockProvider
	httpClient v20240216.HttpRequestDoer
)

func TestOrchestrationClientPact(t *testing.T) {
	setupPact(t)

	flow := scans.Flow{}
	flowErr := flow.UnmarshalJSON([]byte(`{"name": "ide_test"}`))
	require.NoError(t, flowErr)

	createScanData := struct {
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
			Flow:         flow,
			WorkspaceUrl: fmt.Sprintf("http://workspace-service/workspaces/%s", workspaceId),
			WorkspaceId:  &workspaceUUID,
			ScanOptions:  scanOptions,
		},
		Type: "workspace",
	}

	// https://snyk.roadie.so/catalog/default/api/orchestration-service_2024-02-16_experimental
	t.Run("Create scan", func(t *testing.T) {
		pact.AddInteraction().Given("New scan").UponReceiving("Trigger scan").WithCompleteRequest(consumer.Request{
			Method: "POST",
			Path:   matchers.String(fmt.Sprintf("/orgs/%s/scans", orgUUID)),
			Query: matchers.MapMatcher{
				"version": matchers.String("2024-02-16~experimental"),
			},
			Headers: getHeaderMatcher(),
			Body:    getBodyMatcher(),
		}).WithCompleteResponse(consumer.Response{
			Status:  201,
			Headers: getResponseHeaderMatcher(),
			Body:    getResponseBodyMatcher(),
		})

		test := func(config consumer.MockServerConfig) error {
			client, err := v20240216.NewClientWithResponses(fmt.Sprintf("http://localhost:%d", config.Port), v20240216.WithHTTPClient(httpClient))
			require.NoError(t, err)
			_, err = client.CreateScanWorkspaceJobForUserWithApplicationVndAPIPlusJSONBodyWithResponse(
				context.Background(),
				uuid.MustParse(orgUUID),
				&v20240216.CreateScanWorkspaceJobForUserParams{
					Version: "2024-02-16~experimental",
				},
				v20240216.CreateScanWorkspaceJobForUserApplicationVndAPIPlusJSONRequestBody{Data: createScanData})
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

	t.Run("Create incremental scan", func(t *testing.T) {
		pact.AddInteraction().Given("New incremental scan").UponReceiving("Trigger new incremental scan").WithCompleteRequest(consumer.Request{
			Method: "POST",
			Path:   matchers.String(fmt.Sprintf("/orgs/%s/scans", orgUUID)),
			Query: matchers.MapMatcher{
				"version": matchers.String("2024-02-16~experimental"),
			},
			Headers: getHeaderMatcher(),
			Body:    getBodyMatcherForIncrementalScan(),
		}).WithCompleteResponse(consumer.Response{
			Status:  201,
			Headers: getResponseHeaderMatcher(),
			Body:    getResponseBodyMatcher(),
		})

		data := createScanData
		data.Attributes.ScanOptions = scanOptionsIncrementalScan

		test := func(config consumer.MockServerConfig) error {
			client, err := v20240216.NewClientWithResponses(fmt.Sprintf("http://localhost:%d", config.Port), v20240216.WithHTTPClient(httpClient))
			require.NoError(t, err)
			_, err = client.CreateScanWorkspaceJobForUserWithApplicationVndAPIPlusJSONBodyWithResponse(
				context.Background(),
				uuid.MustParse(orgUUID),
				&v20240216.CreateScanWorkspaceJobForUserParams{
					Version: "2024-02-16~experimental",
				},
				v20240216.CreateScanWorkspaceJobForUserApplicationVndAPIPlusJSONRequestBody{Data: data})
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

	t.Run("Get scan", func(t *testing.T) {
		id := uuid.New()

		pact.AddInteraction().Given("Scan ID").UponReceiving("Retrieve scan").WithCompleteRequest(consumer.Request{
			Method: "GET",
			Path:   matchers.String(fmt.Sprintf("/orgs/%s/scans/%s", orgUUID, id.String())),
			Query: matchers.MapMatcher{
				"version": matchers.String("2024-02-16~experimental"),
			},
			Headers: matchers.MapMatcher{},
		}).WithCompleteResponse(consumer.Response{
			Status: 201,
			Headers: matchers.MapMatcher{
				"Content-Type": matchers.String(" application/vnd.api+json"),
			},
			Body: scans.ScanResultsResponse{},
		})

		test := func(config consumer.MockServerConfig) error {
			client, err := v20240216.NewClientWithResponses(fmt.Sprintf("http://localhost:%d", config.Port), v20240216.WithHTTPClient(httpClient))
			require.NoError(t, err)
			_, err = client.GetScanWorkspaceJobForUserWithResponse(
				context.Background(),
				uuid.MustParse(orgUUID),
				id,
				&v20240216.GetScanWorkspaceJobForUserParams{Version: "2024-02-16~experimental"})
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

func getResponseHeaderMatcher() matchers.MapMatcher {
	return matchers.MapMatcher{
		"Content-Type": matchers.String("application/vnd.api+json"),
	}
}

func getResponseBodyMatcher() matchers.Matcher {
	return matchers.Like(map[string]interface{}{
		"data": matchers.Like(map[string]interface{}{
			"attributes": matchers.Like(map[string]interface{}{
				"created_at": matchers.Timestamp(),
				"status":     matchers.String("success"),
			}),
			"type": matchers.String("workspace"),
		}),
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

	require.NoError(t, err)

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
		"Content-Type": matchers.S("application/vnd.api+json"),
	}
}

func getBodyMatcher() matchers.Matcher {
	return matchers.Like(map[string]interface{}{
		"data": matchers.Like(map[string]interface{}{
			"attributes": matchers.Like(map[string]interface{}{
				"flow": matchers.MapMatcher{
					"name": matchers.String("ide_test"),
				},
				"workspace_id":  getWorkspaceUUIDMatcher(),
				"workspace_url": getWorkspaceIDMatcher(),
			}),
			"type": matchers.String("ide"),
		}),
	})
}

func getBodyMatcherForIncrementalScan() matchers.Matcher {
	return matchers.Like(map[string]interface{}{
		"data": matchers.Like(map[string]interface{}{
			"attributes": matchers.Like(map[string]interface{}{
				"flow": matchers.MapMatcher{
					"name": matchers.String("ide_test"),
				},
				"scan_options": matchers.MapMatcher{
					"limit_scan_to_files": getIncrementalScanOptionsMatcher(),
				},
				"workspace_id":  getWorkspaceUUIDMatcher(),
				"workspace_url": getWorkspaceIDMatcher(),
			}),
			"type": matchers.String("ide"),
		}),
	})
}

func getIncrementalScanOptionsMatcher() matchers.Matcher {
	return matchers.ArrayMinLike("fileA", 2)
}

func getWorkspaceIDMatcher() matchers.Matcher {
	return matchers.Regex("http://workspace-service/workspaces/fc763eba-0905-41c5-a27f-3934ab26786c", uuidTailRegex)
}

func getWorkspaceUUIDMatcher() matchers.Matcher {
	return matchers.Regex("fc763eba-0905-41c5-a27f-3934ab26786c", uuidRegex)
}
