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
	"github.com/snyk/go-application-framework/pkg/workflow"
	"net/http"
	"testing"

	"github.com/pact-foundation/pact-go/dsl"
	"github.com/snyk/code-client-go/internal/deepcode"
	"github.com/snyk/code-client-go/internal/util"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"

	codeClientHTTP "github.com/snyk/code-client-go/internal/http"
	"github.com/snyk/code-client-go/internal/util/testutil"
	"github.com/snyk/code-client-go/observability"
)

const (
	consumer     = "SnykLS"
	pactDir      = "./pacts"
	pactProvider = "SnykCodeApi"

	orgUUID             = "00000000-0000-0000-0000-000000000023"
	sessionTokenMatcher = "^token [0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
	uuidMatcher         = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)

// Common test data
var pact dsl.Pact
var client deepcode.SnykCodeClient

func TestSnykCodeBackendServicePact(t *testing.T) {
	snykCodeApiUrl := setupPact(t)
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
			bundleHash, missingFiles, err := client.CreateBundle(context.Background(), snykCodeApiUrl, files)

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
			_, _, err := client.CreateBundle(context.Background(), snykCodeApiUrl, files)

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

			extendedBundleHash, missingFiles, err := client.ExtendBundle(context.Background(), snykCodeApiUrl, bundleHash, filesExtend, removedFiles)

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
			if _, err := client.GetFilters(context.Background(), snykCodeApiUrl); err != nil {
				return err
			}

			return nil
		}

		err := pact.Verify(test)

		assert.NoError(t, err)
	})
}

func setupPact(t *testing.T) string {
	t.Helper()

	config := configuration.NewInMemory()
	config.Set(configuration.ORGANIZATION, orgUUID)
	config.Set(configuration.AUTHENTICATION_TOKEN, "00000000-0000-0000-0000-000000000001")

	engine := workflow.NewWorkFlowEngine(config)

	pact = dsl.Pact{
		Consumer: consumer,
		Provider: pactProvider,
		PactDir:  pactDir,
	}

	// Proactively start service to get access to the port
	pact.Setup(true)
	snykCodeApiUrl := fmt.Sprintf("http://localhost:%d", pact.Server.Port)
	additionalURLs := config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS)
	additionalURLs = append(additionalURLs, snykCodeApiUrl)
	config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, additionalURLs)

	instrumentor := testutil.NewTestInstrumentor()
	errorReporter := testutil.NewTestErrorReporter()
	httpClient := codeClientHTTP.NewHTTPClient(engine, func() *http.Client {
		return engine.GetNetworkAccess().GetHttpClient()
	}, instrumentor, errorReporter, observability.ErrorReporterOptions{})
	client = deepcode.NewSnykCodeClient(engine, httpClient, instrumentor)

	return snykCodeApiUrl
}

func getPutPostHeaderMatcher() dsl.MapMatcher {
	return dsl.MapMatcher{
		"Content-Type":     dsl.String("application/octet-stream"),
		"Content-Encoding": dsl.String("gzip"),
		"Session-Token":    dsl.Regex("token fc763eba-0905-41c5-a27f-3934ab26786c", sessionTokenMatcher),
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
	snykCodeApiUrl := setupPact(t)

	defer pact.Teardown()

	pact.AddInteraction().UponReceiving("Get filters").WithRequest(dsl.Request{
		Method: "GET",
		Path:   dsl.String("/filters"),
		Headers: dsl.MapMatcher{
			"Content-Type":    dsl.String("application/json"),
			"snyk-request-id": getSnykRequestIdMatcher(),
			"Session-Token":   dsl.Regex("token fc763eba-0905-41c5-a27f-3934ab26786c", sessionTokenMatcher),
			"Authorization":   dsl.Regex("token fc763eba-0905-41c5-a27f-3934ab26786c", sessionTokenMatcher),
		},
	}).WillRespondWith(dsl.Response{
		Status: 200,
		Headers: dsl.MapMatcher{
			"Content-Type": dsl.String("application/json"),
		},
		Body: dsl.Match(deepcode.FiltersResponse{}),
	})

	test := func() error {
		if _, err := client.GetFilters(context.Background(), snykCodeApiUrl); err != nil {
			return err
		}
		return nil
	}

	err := pact.Verify(test)

	assert.NoError(t, err)
}
