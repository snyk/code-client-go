//go:build contract

package v20241221_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/oapi-codegen/runtime/types"
	"github.com/pact-foundation/pact-go/v2/consumer"
	"github.com/pact-foundation/pact-go/v2/matchers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	codeClientHTTP "github.com/snyk/code-client-go/http"
	testapi "github.com/snyk/code-client-go/internal/api/test/2024-12-21"
	v20241221 "github.com/snyk/code-client-go/internal/api/test/2024-12-21/models"
	"github.com/snyk/code-client-go/internal/util/testutil"
)

const (
	consumerName = "code-client-go"
	pactDir      = "./pacts"
	pactProvider = "test-service"
	orgUUID      = "e7ea34c9-de0f-422c-bf2c-4654c2e2da90"
	testId       = "b7ea34c9-de0f-4a2c-bf2c-4654c2e2da90"
)

var (
	pact       *consumer.V2HTTPMockProvider
	httpClient testapi.HttpRequestDoer
)

func loadTestResultFixture(t *testing.T, path string) matchers.Matcher {
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	var m map[string]interface{}
	err = json.Unmarshal(data, &m)
	require.NoError(t, err)
	return matchers.Like(m)
}

func TestTestClientPact(t *testing.T) {
	setupPact(t)

	t.Run("Create test", func(t *testing.T) {
		ctx := context.Background()
		params := &testapi.CreateTestParams{
			Version: "2024-12-21",
		}

		pact.AddInteraction().
			Given("Create new test").
			UponReceiving("A request to create test").
			WithCompleteRequest(consumer.Request{
				Method: "POST",
				Path:   matchers.Regex("/orgs/e7ea34c9-de0f-422c-bf2c-4654c2e2da90/tests", "/orgs/"+orgUUID+"/tests"),
				Query: map[string]matchers.Matcher{
					"version": matchers.Term("2024-12-21", "2024-12-21"),
				},
				Headers: map[string]matchers.Matcher{
					"Content-Type": matchers.Includes("application/vnd.api+json"),
				},
				Body: matchers.Like(map[string]interface{}{
					"data": map[string]interface{}{
						"type": "test",
						"attributes": map[string]interface{}{
							"configuration": map[string]interface{}{
								"scan": map[string]interface{}{
									"result_type": "code_security",
								},
							},
							"input": map[string]interface{}{
								"type":      "bundle",
								"bundle_id": "bundle-123",
								"metadata": map[string]interface{}{
									"local_file_path": "/path/to/file",
								},
							},
						},
					},
				}),
			}).
			WithCompleteResponse(consumer.Response{
				Status: 201,
				Headers: matchers.MapMatcher{
					"Content-Type": matchers.Term("application/vnd.api+json", "application/vnd.api+json"),
				},
				Body: matchers.Like(map[string]interface{}{
					"data": map[string]interface{}{
						"type": "test",
						"id":   testId,
					},
					"links": map[string]interface{}{
						"self": fmt.Sprintf("http://localhost/orgs/%s/tests/%s", orgUUID, testId),
					},
				}),
			})

		test := func(config consumer.MockServerConfig) error {
			client, err := testapi.NewClientWithResponses(fmt.Sprintf("http://localhost:%d", config.Port), testapi.WithHTTPClient(httpClient))
			require.NoError(t, err)

			orgId := uuid.MustParse(orgUUID)

			body, err := createTestBody()
			require.NoError(t, err)

			_, err = client.CreateTestWithApplicationVndAPIPlusJSONBody(ctx, orgId, params, body)
			if err != nil {
				return err
			}
			return nil
		}

		if err := pact.ExecuteTest(t, test); err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
	})

	t.Run("Get test result", func(t *testing.T) {
		ctx := context.Background()
		params := &testapi.GetTestResultParams{
			Version: "2024-12-21",
		}

		pact.AddInteraction().
			Given("Test exists").
			UponReceiving("A request to get test result").
			WithCompleteRequest(consumer.Request{
				Method: "GET",
				Path:   matchers.Regex("/orgs/e7ea34c9-de0f-422c-bf2c-4654c2e2da90/tests/e7ea34c9-de0f-422c-bf2c-4654c2e2da90", "/orgs/"+orgUUID+"/tests/"+testId),
				Query: map[string]matchers.Matcher{
					"version": matchers.Term("2024-12-21", "2024-12-21"),
				},
			}).
			WithCompleteResponse(consumer.Response{
				Status: 200,
				Headers: matchers.MapMatcher{
					"Content-Type": matchers.Regex("(?i)application/json(;\\s?charset=utf-8)?", "application/json; charset=utf-8"),
				},
				Body: loadTestResultFixture(t, "testdata/test_result.json"),
			})
		test := func(config consumer.MockServerConfig) error {
			client, err := testapi.NewClientWithResponses(fmt.Sprintf("http://localhost:%d", config.Port), testapi.WithHTTPClient(httpClient))
			require.NoError(t, err)

			orgId := uuid.MustParse(orgUUID)
			testID := uuid.MustParse(testId)
			_, err = client.GetTestResult(ctx, orgId, testID, params)
			if err != nil {
				return err
			}
			return err
		}

		if err := pact.ExecuteTest(t, test); err != nil {
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
	require.NoError(t, err)

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
}

func getResponseHeaderMatcher() map[string]matchers.Matcher {
	return map[string]matchers.Matcher{
		"Content-Type": matchers.Regex("(?i)application/json(;\\s?charset=utf-8)?", "application/json; charset=utf-8"),
	}
}

func createTestBody() (v20241221.CreateTestRequestBody, error) {
	resultType := v20241221.CodeSecurity
	body := v20241221.CreateTestRequestBody{
		Data: struct {
			Attributes struct {
				Configuration struct {
					Output *struct {
						Label           *string     `json:"label,omitempty"`
						ProjectId       *types.UUID `json:"project_id,omitempty"`
						ProjectName     *string     `json:"project_name,omitempty"`
						Report          *bool       `json:"report,omitempty"`
						TargetName      *string     `json:"target_name,omitempty"`
						TargetReference *string     `json:"target_reference,omitempty"`
					} `json:"output,omitempty"`
					Scan struct {
						ResultType *v20241221.Scan `json:"result_type,omitempty"`
					} `json:"scan"`
				} `json:"configuration"`
				Input v20241221.CreateTestRequestBody_Data_Attributes_Input `json:"input"`
			} `json:"attributes"`
			Type v20241221.CreateTestRequestBodyDataType `json:"type"`
		}{
			Type: v20241221.CreateTestRequestBodyDataTypeTest,
			Attributes: struct {
				Configuration struct {
					Output *struct {
						Label           *string     `json:"label,omitempty"`
						ProjectId       *types.UUID `json:"project_id,omitempty"`
						ProjectName     *string     `json:"project_name,omitempty"`
						Report          *bool       `json:"report,omitempty"`
						TargetName      *string     `json:"target_name,omitempty"`
						TargetReference *string     `json:"target_reference,omitempty"`
					} `json:"output,omitempty"`
					Scan struct {
						ResultType *v20241221.Scan `json:"result_type,omitempty"`
					} `json:"scan"`
				} `json:"configuration"`
				Input v20241221.CreateTestRequestBody_Data_Attributes_Input `json:"input"`
			}{
				Configuration: struct {
					Output *struct {
						Label           *string     `json:"label,omitempty"`
						ProjectId       *types.UUID `json:"project_id,omitempty"`
						ProjectName     *string     `json:"project_name,omitempty"`
						Report          *bool       `json:"report,omitempty"`
						TargetName      *string     `json:"target_name,omitempty"`
						TargetReference *string     `json:"target_reference,omitempty"`
					} `json:"output,omitempty"`
					Scan struct {
						ResultType *v20241221.Scan `json:"result_type,omitempty"`
					} `json:"scan"`
				}{
					Scan: struct {
						ResultType *v20241221.Scan `json:"result_type,omitempty"`
					}{
						ResultType: &resultType,
					},
				},
			},
		},
	}
	input := v20241221.TestInputBundle{
		Type:     v20241221.Bundle,
		BundleId: "bundle-123",
		Metadata: struct {
			LimitTestToFiles *[]string `json:"limit_test_to_files,omitempty"`
			LocalFilePath    string    `json:"local_file_path"`
			RepoUrl          *string   `json:"repo_url,omitempty"`
		}{
			LocalFilePath: "/path/to/file",
		},
	}
	err := body.Data.Attributes.Input.FromTestInputBundle(input)
	if err != nil {
		return body, err
	}
	return body, nil
}
