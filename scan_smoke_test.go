//go:build smoke

/*
 * © 2024 Snyk Limited All rights reserved.
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
package codeclient_test

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	codeClient "github.com/snyk/code-client-go"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	scans "github.com/snyk/code-client-go/internal/orchestration/2024-02-16/scans"
	"github.com/snyk/code-client-go/internal/util/testutil"
	"github.com/snyk/code-client-go/scan"
)

func TestSmoke_Scan_IDE(t *testing.T) {
	var cloneTargetDir, err = testutil.SetupCustomTestRepo(t, "https://github.com/snyk-labs/nodejs-goof", "0336589", "", "")
	assert.NoError(t, err)

	target, err := scan.NewRepositoryTarget(cloneTargetDir)
	assert.NoError(t, err)

	files := sliceToChannel([]string{filepath.Join(cloneTargetDir, "app.js"), filepath.Join(cloneTargetDir, "utils.js")})

	logger := zerolog.New(os.Stdout).Level(zerolog.TraceLevel)
	instrumentor := testutil.NewTestInstrumentor()
	errorReporter := testutil.NewTestErrorReporter()
	config := testutil.NewTestConfig()
	httpClient := codeClientHTTP.NewHTTPClient(
		func() *http.Client {
			client := http.Client{
				Timeout:   time.Duration(180) * time.Second,
				Transport: testutil.TestAuthRoundTripper{http.DefaultTransport},
			}
			return &client
		},
		codeClientHTTP.WithRetryCount(3),
		codeClientHTTP.WithLogger(&logger),
		codeClientHTTP.WithInstrumentor(instrumentor),
	)
	trackerFactory := scan.NewNoopTrackerFactory()

	codeScanner := codeClient.NewCodeScanner(
		config,
		httpClient,
		codeClient.WithTrackerFactory(trackerFactory),
		codeClient.WithLogger(&logger),
		codeClient.WithInstrumentor(instrumentor),
		codeClient.WithErrorReporter(errorReporter),
	)

	// let's have a requestID that does not change
	span := instrumentor.StartSpan(context.Background(), "UploadAndAnalyze")
	defer span.Finish()

	response, bundleHash, scanErr := codeScanner.UploadAndAnalyze(span.Context(), uuid.New().String(), target, files, map[string]bool{})
	require.NoError(t, scanErr)
	require.NotEmpty(t, bundleHash)
	require.NotNil(t, response)
	require.Greater(t, len(response.Sarif.Runs), 0)
	require.Greater(t, len(response.Sarif.Runs[0].Results), 0)
	require.Greater(t, len(response.Sarif.Runs[0].Results[0].Locations), 0)
	require.NotNil(t, response.Sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
}

func Test_SmokeScan_CLI(t *testing.T) {
	var cloneTargetDir, err = testutil.SetupCustomTestRepo(t, "https://github.com/snyk-labs/nodejs-goof", "0336589", "", "")
	assert.NoError(t, err)

	target, err := scan.NewRepositoryTarget(cloneTargetDir)
	assert.NoError(t, err)

	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}
	files := sliceToChannel([]string{filepath.Join(cloneTargetDir, "app.js"), filepath.Join(cloneTargetDir, "utils.js")})

	logger := zerolog.New(os.Stdout).Level(zerolog.TraceLevel)
	instrumentor := testutil.NewTestInstrumentor()
	errorReporter := testutil.NewTestErrorReporter()
	config := testutil.NewTestConfig()
	httpClient := codeClientHTTP.NewHTTPClient(
		func() *http.Client {
			client := http.Client{
				Timeout:   time.Duration(180) * time.Second,
				Transport: testutil.TestAuthRoundTripper{http.DefaultTransport},
			}
			return &client
		},
		codeClientHTTP.WithRetryCount(3),
		codeClientHTTP.WithLogger(&logger),
		codeClientHTTP.WithInstrumentor(instrumentor),
	)
	trackerFactory := scan.NewNoopTrackerFactory()

	codeScanner := codeClient.NewCodeScanner(
		config,
		httpClient,
		codeClient.WithTrackerFactory(trackerFactory),
		codeClient.WithLogger(&logger),
		codeClient.WithInstrumentor(instrumentor),
		codeClient.WithErrorReporter(errorReporter),
		codeClient.WithFlow(string(scans.CliTest)),
	)

	// let's have a requestID that does not change
	span := instrumentor.StartSpan(context.Background(), "UploadAndAnalyze")
	defer span.Finish()

	response, bundleHash, scanErr := codeScanner.UploadAndAnalyze(span.Context(), uuid.New().String(), target, files, map[string]bool{})
	require.NoError(t, scanErr)
	require.NotEmpty(t, bundleHash)
	require.NotNil(t, response)
	require.Greater(t, len(response.Sarif.Runs), 0)
	require.Greater(t, len(response.Sarif.Runs[0].Results), 0)
	require.Greater(t, len(response.Sarif.Runs[0].Results[0].Locations), 0)
	require.NotNil(t, response.Sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
}

func TestSmoke_Scan_SubFolder(t *testing.T) {
	currDir, err := os.Getwd()
	require.NoError(t, err)
	cloneTargetDir := filepath.Join(currDir, "internal/util")

	target, err := scan.NewRepositoryTarget(cloneTargetDir)
	assert.NoError(t, err)

	files := sliceToChannel([]string{filepath.Join(cloneTargetDir, "hash.go")})

	logger := zerolog.New(os.Stdout)
	instrumentor := testutil.NewTestInstrumentor()
	errorReporter := testutil.NewTestErrorReporter()
	config := testutil.NewTestConfig()
	httpClient := codeClientHTTP.NewHTTPClient(
		func() *http.Client {
			client := http.Client{
				Timeout:   time.Duration(180) * time.Second,
				Transport: testutil.TestAuthRoundTripper{http.DefaultTransport},
			}
			return &client
		},
		codeClientHTTP.WithRetryCount(3),
		codeClientHTTP.WithLogger(&logger),
	)
	trackerFactory := scan.NewNoopTrackerFactory()

	codeScanner := codeClient.NewCodeScanner(
		config,
		httpClient,
		codeClient.WithTrackerFactory(trackerFactory),
		codeClient.WithInstrumentor(instrumentor),
		codeClient.WithErrorReporter(errorReporter),
		codeClient.WithLogger(&logger),
	)

	// let's have a requestID that does not change
	span := instrumentor.StartSpan(context.Background(), "UploadAndAnalyze")
	defer span.Finish()

	response, bundleHash, scanErr := codeScanner.UploadAndAnalyze(span.Context(), uuid.New().String(), target, files, map[string]bool{})
	require.NoError(t, scanErr)
	require.NotEmpty(t, bundleHash)
	require.NotNil(t, response)
}
