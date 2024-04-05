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
	"github.com/pact-foundation/pact-go/dsl"
	"github.com/stretchr/testify/assert"

	confMocks "github.com/snyk/code-client-go/config/mocks"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/internal/deepcode"
	"github.com/snyk/code-client-go/internal/util"
	"github.com/snyk/code-client-go/internal/util/testutil"
)

const (
	consumer     = "SnykLS"
	pactDir      = "./pacts"
	pactProvider = "SnykCodeApi"

	orgUUID     = "00000000-0000-0000-0000-000000000023"
	uuidMatcher = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

// Common test data
var pact dsl.Pact
var client deepcode.SnykCodeClient

func TestSnykCodeBackendServicePact(t *testing.T) {
	setupPact(t)
	defer pact.Teardown()

	defer func() {
		if err := pact.WritePact(); err != nil {
			t.Fatal(err)
		}
	}()

	t.Run("Create bundle", func(t *testing.T) {
		pact.AddInteraction().Given("New bundle").UponReceiving("Create bundle").WithRequest(dsl.Request{
			Method:  "POST",
			Path:    dsl.String("/bundle"),
			Headers: getPutPostHeaderMatcher(),
			Body:    getPutPostBodyMatcher(),
		}).WillRespondWith(dsl.Response{
			Status: 200,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			Body: dsl.Match(deepcode.BundleResponse{}),
		})

		test := func() error {
			files := make(map[string]string)
			files[path1] = util.Hash([]byte(content))
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

		err := pact.Verify(test)

		if err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
	})

	t.Run("Create bundle with invalid token", func(t *testing.T) {
		pact.AddInteraction().Given("New bundle and invalid token").UponReceiving("Create bundle").WithRequest(dsl.Request{
			Method:  "POST",
			Path:    dsl.String("/bundle"),
			Headers: getPutPostHeaderMatcher(),
			Body:    getPutPostBodyMatcher(),
		}).WillRespondWith(dsl.Response{
			Status: 401,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json; charset=utf-8"),
			},
			Body: map[string]string{
				"message": "Invalid auth token provided",
			},
		})

		test := func() error {
			files := make(map[string]string)
			files[path1] = util.Hash([]byte(content))
			_, _, err := client.CreateBundle(context.Background(), files)

			if err != nil {
				return nil
			}

			return fmt.Errorf("no error returned")
		}

		err := pact.Verify(test)

		if err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
	})

	t.Run("Extend bundle", func(*testing.T) {
		bundleHash := "faa6b7161c14f933ef4ca79a18ad9283eab362d5e6d3a977125eb95b37c377d8"

		pact.AddInteraction().Given("Existing bundle").UponReceiving("Extend bundle").WithRequest(dsl.Request{
			Method:  "PUT",
			Path:    dsl.Term("/bundle/"+bundleHash, "/bundle/[A-Fa-f0-9]{64}"),
			Headers: getPutPostHeaderMatcher(),
			Body:    getPutPostBodyMatcher(),
		}).WillRespondWith(dsl.Response{
			Status: 200,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			Body: dsl.Match(deepcode.BundleResponse{}),
		})

		test := func() error {
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

		err := pact.Verify(test)

		if err != nil {
			t.Fatalf("Error on verify: %v", err)
		}
	})

	t.Run("Get filters", func(*testing.T) {
		pact.AddInteraction().UponReceiving("Get filters").WithRequest(dsl.Request{
			Method: "GET",
			Path:   dsl.String("/filters"),
			Headers: dsl.MapMatcher{
				"Content-Type":    dsl.String("application/json"),
				"snyk-request-id": getSnykRequestIdMatcher(),
			},
		}).WillRespondWith(dsl.Response{
			Status: 200,
			Headers: dsl.MapMatcher{
				"Content-Type": dsl.String("application/json"),
			},
			Body: dsl.Match(deepcode.FiltersResponse{}),
		})

		test := func() error {
			if _, err := client.GetFilters(context.Background()); err != nil {
				return err
			}

			return nil
		}

		err := pact.Verify(test)

		assert.NoError(t, err)
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
	ctrl := gomock.NewController(t)
	config := confMocks.NewMockConfig(ctrl)
	config.EXPECT().IsFedramp().AnyTimes().Return(false)
	config.EXPECT().Organization().AnyTimes().Return(orgUUID)
	snykCodeApiUrl := fmt.Sprintf("http://localhost:%d", pact.Server.Port)
	config.EXPECT().SnykCodeApi().AnyTimes().Return(snykCodeApiUrl)

	instrumentor := testutil.NewTestInstrumentor()
	errorReporter := testutil.NewTestErrorReporter()
	httpClient := codeClientHTTP.NewHTTPClient(newLogger(t), func() *http.Client {
		return http.DefaultClient
	}, instrumentor, errorReporter)
	client = deepcode.NewSnykCodeClient(newLogger(t), httpClient, instrumentor, errorReporter, config)
}

func getPutPostHeaderMatcher() dsl.MapMatcher {
	return dsl.MapMatcher{
		"Content-Type":     dsl.String("application/octet-stream"),
		"Content-Encoding": dsl.String("gzip"),
		"snyk-org-name":    dsl.Regex(orgUUID, uuidMatcher),
		"snyk-request-id":  getSnykRequestIdMatcher(),
	}
}

func getPutPostBodyMatcher() dsl.Matcher {
	return dsl.Like(make([]byte, 1))
}

func getSnykRequestIdMatcher() dsl.Matcher {
	return dsl.Regex("fc763eba-0905-41c5-a27f-3934ab26786c", uuidMatcher)
}

func TestSnykCodeBackendServicePact_LocalCodeEngine(t *testing.T) {
	setupPact(t)

	defer pact.Teardown()

	pact.AddInteraction().UponReceiving("Get filters").WithRequest(dsl.Request{
		Method: "GET",
		Path:   dsl.String("/filters"),
		Headers: dsl.MapMatcher{
			"Content-Type":    dsl.String("application/json"),
			"snyk-request-id": getSnykRequestIdMatcher(),
		},
	}).WillRespondWith(dsl.Response{
		Status: 200,
		Headers: dsl.MapMatcher{
			"Content-Type": dsl.String("application/json"),
		},
		Body: dsl.Match(deepcode.FiltersResponse{}),
	})

	test := func() error {
		if _, err := client.GetFilters(context.Background()); err != nil {
			return err
		}
		return nil
	}

	err := pact.Verify(test)

	assert.NoError(t, err)
}
