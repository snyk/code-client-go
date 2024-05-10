//go:build SMOKE

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
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"

	codeClient "github.com/snyk/code-client-go"
	codeClientHTTP "github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/internal/util/testutil"
	"github.com/snyk/code-client-go/scan"
)

func Test_SmokeScan_HTTPS(t *testing.T) {
	if os.Getenv("SMOKE_TESTS") != "true" {
		t.Skip()
	}
	var cloneTargetDir, err = setupCustomTestRepo(t, "https://github.com/snyk-labs/nodejs-goof", "0336589")
	assert.NoError(t, err)

	target, err := scan.NewRepositoryTarget(cloneTargetDir)
	assert.NoError(t, err)

	defer func(path string) { _ = os.RemoveAll(path) }(cloneTargetDir)
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
				Transport: TestAuthRoundTripper{http.DefaultTransport},
			}
			return &client
		},
		codeClientHTTP.WithRetryCount(3),
		codeClientHTTP.WithLogger(&logger),
	)

	codeScanner := codeClient.NewCodeScanner(
		config,
		httpClient,
		codeClient.WithLogger(&logger), codeClient.WithInstrumentor(instrumentor), codeClient.WithErrorReporter(errorReporter))
	response, bundleHash, scanErr := codeScanner.UploadAndAnalyze(context.Background(), uuid.New().String(), target, files, map[string]bool{})
	require.NoError(t, scanErr)
	require.NotEmpty(t, bundleHash)
	require.NotNil(t, response)
	require.Greater(t, len(response.Sarif.Runs), 0)
	require.Greater(t, len(response.Sarif.Runs[0].Results), 0)
	require.Greater(t, len(response.Sarif.Runs[0].Results[0].Locations), 0)
	require.NotNil(t, response.Sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
}

func Test_SmokeScan_SSH(t *testing.T) {
	if os.Getenv("SMOKE_TESTS") != "true" {
		t.Skip()
	}
	var cloneTargetDir, err = setupCustomTestRepo(t, "git@github.com:snyk-labs/nodejs-goof", "0336589")
	assert.NoError(t, err)

	target, err := scan.NewRepositoryTarget(cloneTargetDir)
	assert.NoError(t, err)

	defer func(path string) { _ = os.RemoveAll(path) }(cloneTargetDir)
	if err != nil {
		t.Fatal(err, "Couldn't setup test repo")
	}
	files := sliceToChannel([]string{filepath.Join(cloneTargetDir, "app.js"), filepath.Join(cloneTargetDir, "utils.js")})

	logger := zerolog.New(os.Stdout)
	instrumentor := testutil.NewTestInstrumentor()
	errorReporter := testutil.NewTestErrorReporter()
	config := testutil.NewTestConfig()
	httpClient := codeClientHTTP.NewHTTPClient(
		func() *http.Client {
			client := http.Client{
				Timeout:   time.Duration(180) * time.Second,
				Transport: TestAuthRoundTripper{http.DefaultTransport},
			}
			return &client
		},
		codeClientHTTP.WithRetryCount(3),
		codeClientHTTP.WithLogger(&logger),
	)

	codeScanner := codeClient.NewCodeScanner(
		config,
		httpClient,
		codeClient.WithInstrumentor(instrumentor),
		codeClient.WithErrorReporter(errorReporter),
		codeClient.WithLogger(&logger),
	)
	response, bundleHash, scanErr := codeScanner.UploadAndAnalyze(context.Background(), uuid.New().String(), target, files, map[string]bool{})
	require.NoError(t, scanErr)
	require.NotEmpty(t, bundleHash)
	require.NotNil(t, response)
}

func Test_SmokeScan_SubFolder(t *testing.T) {
	if os.Getenv("SMOKE_TESTS") != "true" {
		t.Skip()
	}
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
				Transport: TestAuthRoundTripper{http.DefaultTransport},
			}
			return &client
		},
		codeClientHTTP.WithRetryCount(3),
		codeClientHTTP.WithLogger(&logger),
	)

	codeScanner := codeClient.NewCodeScanner(
		config,
		httpClient,
		codeClient.WithInstrumentor(instrumentor),
		codeClient.WithErrorReporter(errorReporter),
		codeClient.WithLogger(&logger),
	)
	response, bundleHash, scanErr := codeScanner.UploadAndAnalyze(context.Background(), uuid.New().String(), target, files, map[string]bool{})
	require.NoError(t, scanErr)
	require.NotEmpty(t, bundleHash)
	require.NotNil(t, response)
}

func setupCustomTestRepo(t *testing.T, url string, targetCommit string) (string, error) {
	t.Helper()
	tempDir := t.TempDir()
	repoDir := "1"
	absoluteCloneRepoDir := filepath.Join(tempDir, repoDir)
	cmd := []string{"clone", url, repoDir}
	log.Debug().Interface("cmd", cmd).Msg("clone command")
	clone := exec.Command("git", cmd...)
	clone.Dir = tempDir
	reset := exec.Command("git", "reset", "--hard", targetCommit)
	reset.Dir = absoluteCloneRepoDir

	clean := exec.Command("git", "clean", "--force")
	clean.Dir = absoluteCloneRepoDir

	output, err := clone.CombinedOutput()
	if err != nil {
		t.Fatal(err, "clone didn't work")
	}

	log.Debug().Msg(string(output))
	output, _ = reset.CombinedOutput()

	log.Debug().Msg(string(output))
	output, err = clean.CombinedOutput()

	log.Debug().Msg(string(output))
	return absoluteCloneRepoDir, err
}

type TestAuthRoundTripper struct {
	http.RoundTripper
}

func (tart TestAuthRoundTripper) RoundTrip(req *http.Request) (res *http.Response, e error) {
	token := os.Getenv("SMOKE_TEST_TOKEN")
	req.Header.Set("Authorization", fmt.Sprintf("token %s", token))
	req.Header.Set("session_token", token)
	return tart.RoundTripper.RoundTrip(req)
}
