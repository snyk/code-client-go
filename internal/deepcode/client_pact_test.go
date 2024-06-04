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

package deepcode_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/pact-foundation/pact-go/v2/consumer"
	"github.com/pact-foundation/pact-go/v2/matchers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	confMocks "github.com/snyk/code-client-go/config/mocks"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/internal/deepcode"
	"github.com/snyk/code-client-go/internal/util"
	"github.com/snyk/code-client-go/internal/util/testutil"
)

const (
	consumerName = "code-client-go"
	pactDir      = "./pacts"
	pactProvider = "SnykCodeApi"

	orgUUID     = "00000000-0000-0000-0000-000000000023"
	uuidMatcher = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

// Common test data
var (
	pact *consumer.V2HTTPMockProvider
)

func TestSnykCodeClientPact(t *testing.T) {
	setupPact(t)

	t.Run("Create bundle", func(t *testing.T) {
		files := make(map[string]string)
		files[path1] = util.Hash([]byte(content))

		pact.AddInteraction().Given("New bundle").UponReceiving("Create bundle").WithCompleteRequest(consumer.Request{
			Method:  "POST",
			Path:    matchers.String("/bundle"),
			Headers: getPutPostHeaderMatcher(),
		}).WithCompleteResponse(consumer.Response{
			Status: 200,
			Headers: matchers.MapMatcher{
				"Content-Type": matchers.String("application/json"),
			},
			Body: matchers.MatchV2(deepcode.BundleResponse{}),
		})

		test := func(config consumer.MockServerConfig) error {
			client := getDeepCodeClient(t, getLocalMockserver(config))
			bundleHash, missingFiles, err := client.CreateBundle(context.Background(), files)

			if err != nil {
				return err
			}
			if bundleHash == "" {
				return fmt.Errorf("bundleHash is null")
			}
			if len(missingFiles) == 0 {
				return fmt.Errorf("missingFiles are empty")
			}

			return nil
		}

		err := pact.ExecuteTest(t, test)

		if err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
	})

	t.Run("Create bundle with invalid token", func(t *testing.T) {
		pact.AddInteraction().Given("New bundle and invalid token").UponReceiving("Create bundle").WithCompleteRequest(consumer.Request{
			Method:  "POST",
			Path:    matchers.String("/bundle"),
			Headers: getPutPostHeaderMatcher(),
		}).WithCompleteResponse(consumer.Response{
			Status: 401,
			Headers: matchers.MapMatcher{
				"Content-Type": matchers.String("application/json; charset=utf-8"),
			},
			Body: map[string]string{
				"message": "Invalid auth token provided",
			},
		})

		test := func(config consumer.MockServerConfig) error {
			client := getDeepCodeClient(t, getLocalMockserver(config))
			files := make(map[string]string)
			files[path1] = util.Hash([]byte(content))
			_, _, err := client.CreateBundle(context.Background(), files)

			if err != nil {
				return nil
			}

			return fmt.Errorf("no error returned")
		}

		err := pact.ExecuteTest(t, test)

		if err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
	})

	t.Run("Extend bundle", func(*testing.T) {
		bundleHash := "faa6b7161c14f933ef4ca79a18ad9283eab362d5e6d3a977125eb95b37c377d8"

		pact.AddInteraction().Given("Existing bundle").UponReceiving("Extend bundle").WithCompleteRequest(consumer.Request{
			Method:  "PUT",
			Path:    matchers.Term("/bundle/"+bundleHash, "/bundle/[A-Fa-f0-9]{64}"),
			Headers: getPutPostHeaderMatcher(),
		}).WithCompleteResponse(consumer.Response{
			Status: 200,
			Headers: matchers.MapMatcher{
				"Content-Type": matchers.String("application/json"),
			},
			Body: matchers.MatchV2(deepcode.BundleResponse{}),
		})

		test := func(config consumer.MockServerConfig) error {
			client := getDeepCodeClient(t, getLocalMockserver(config))
			filesExtend := createTestExtendMap()
			var removedFiles []string

			extendedBundleHash, missingFiles, err := client.ExtendBundle(context.Background(), bundleHash, filesExtend, removedFiles)

			if err != nil {
				return err
			}
			if extendedBundleHash == "" {
				return fmt.Errorf("bundleHash is empty")
			}
			if len(missingFiles) == 0 {
				return fmt.Errorf("missingFiles are empty")
			}

			return nil
		}

		err := pact.ExecuteTest(t, test)

		if err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
	})

	t.Run("Get filters", func(*testing.T) {
		pact.AddInteraction().UponReceiving("Get filters").WithCompleteRequest(consumer.Request{
			Method: "GET",
			Path:   matchers.String("/filters"),
			Headers: matchers.MapMatcher{
				"Content-Type":    matchers.String("application/json"),
				"snyk-request-id": getSnykRequestIdMatcher(),
			},
		}).WithCompleteResponse(consumer.Response{
			Status: 200,
			Headers: matchers.MapMatcher{
				"Content-Type": matchers.String("application/json"),
			},
			Body: matchers.MatchV2(deepcode.FiltersResponse{}),
		})

		test := func(config consumer.MockServerConfig) error {
			client := getDeepCodeClient(t, getLocalMockserver(config))
			if _, err := client.GetFilters(context.Background()); err != nil {
				return err
			}

			return nil
		}

		err := pact.ExecuteTest(t, test)

		assert.NoError(t, err)
	})
}

func getLocalMockserver(config consumer.MockServerConfig) string {
	return fmt.Sprintf("http://%s:%d", config.Host, config.Port)
}

func setupPact(t *testing.T) {
	t.Helper()

	pactConfig := consumer.MockHTTPProviderConfig{
		Consumer: consumerName,
		Provider: pactProvider,
		PactDir:  pactDir,
	}
	var err error
	pact, err = consumer.NewV2Pact(pactConfig)
	require.NoError(t, err)
}

func getDeepCodeClient(t *testing.T, snykCodeApiUrl string) deepcode.DeepcodeClient {
	t.Helper()
	instrumentor := testutil.NewTestInstrumentor()
	errorReporter := testutil.NewTestErrorReporter()
	httpClient := codeClientHTTP.NewHTTPClient(
		func() *http.Client {
			return http.DefaultClient
		},
		codeClientHTTP.WithRetryCount(1),
		codeClientHTTP.WithInstrumentor(instrumentor),
		codeClientHTTP.WithErrorReporter(errorReporter),
		codeClientHTTP.WithLogger(newLogger(t)),
	)

	ctrl := gomock.NewController(t)
	config := confMocks.NewMockConfig(ctrl)
	config.EXPECT().IsFedramp().AnyTimes().Return(false)
	config.EXPECT().Organization().AnyTimes().Return(orgUUID)
	config.EXPECT().SnykCodeApi().AnyTimes().Return(snykCodeApiUrl)
	return deepcode.NewDeepcodeClient(config, httpClient, newLogger(t), instrumentor, errorReporter)
}

func getPutPostHeaderMatcher() matchers.MapMatcher {
	return matchers.MapMatcher{
		"Content-Type":     matchers.S("application/octet-stream"),
		"Content-Encoding": matchers.S("gzip"),
		"snyk-org-name":    matchers.Regex(orgUUID, uuidMatcher),
		"snyk-request-id":  getSnykRequestIdMatcher(),
	}
}

func getSnykRequestIdMatcher() matchers.Matcher {
	return matchers.Regex("fc763eba-0905-41c5-a27f-3934ab26786c", uuidMatcher)
}

func TestSnykCodeClientPact_LocalCodeEngine(t *testing.T) {
	setupPact(t)

	pact.AddInteraction().UponReceiving("Get filters").WithCompleteRequest(consumer.Request{
		Method: "GET",
		Path:   matchers.String("/filters"),
		Headers: matchers.MapMatcher{
			"Content-Type":    matchers.String("application/json"),
			"snyk-request-id": getSnykRequestIdMatcher(),
		},
	}).WithCompleteResponse(consumer.Response{
		Status: 200,
		Headers: matchers.MapMatcher{
			"Content-Type": matchers.String("application/json"),
		},
		Body: matchers.MatchV2(deepcode.FiltersResponse{}),
	})

	test := func(config consumer.MockServerConfig) error {
		client := getDeepCodeClient(t, getLocalMockserver(config))
		if _, err := client.GetFilters(context.Background()); err != nil {
			return err
		}
		return nil
	}

	err := pact.ExecuteTest(t, test)

	assert.NoError(t, err)
}
