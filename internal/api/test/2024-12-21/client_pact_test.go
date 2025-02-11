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
	"github.com/pact-foundation/pact-go/v2/consumer"
	"github.com/pact-foundation/pact-go/v2/matchers"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	codeClientHTTP "github.com/snyk/code-client-go/http"
	testapi "github.com/snyk/code-client-go/internal/api/test/2024-12-21"
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
			fmt.Println("client created", client)
			require.NoError(t, err)

			orgId := uuid.MustParse(orgUUID)
			testID := uuid.MustParse(testId)
			fmt.Println("Getting test result")
			response, err := client.GetTestResult(ctx, orgId, testID, params)
			fmt.Println("Got test result", response.StatusCode)
			fmt.Println("Got test result", response.Body)
			if err != nil {
				fmt.Println("Error getting test result", err)
				return err
			}
			return err
		}

		if err := pact.ExecuteTest(t, test); err != nil {
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
