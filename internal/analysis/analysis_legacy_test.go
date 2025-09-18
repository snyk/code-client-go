/*
 * © 2025 Snyk Limited All rights reserved.
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
package analysis_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	confMocks "github.com/snyk/code-client-go/config/mocks"
	httpmocks "github.com/snyk/code-client-go/http/mocks"
	"github.com/snyk/code-client-go/internal/analysis"
	"github.com/snyk/code-client-go/observability/mocks"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
	trackerMocks "github.com/snyk/code-client-go/scan/mocks"
)

func mockLegacyAnalysisResponse(t *testing.T, mockHTTPClient *httpmocks.MockHTTPClient, sarifResponse sarif.SarifResponse, bundleHash string, orgId string, responseCode int) {
	t.Helper()
	responseBodyBytes, err := json.Marshal(sarifResponse)
	assert.NoError(t, err)
	expectedAnalysisUrl := "http://localhost/analysis"
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == expectedAnalysisUrl && req.Method == http.MethodPost
	})).Times(1).Return(&http.Response{
		StatusCode: responseCode,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(responseBodyBytes)),
	}, mockDeriveErrorFromStatusCode(responseCode))
}

func setupLegacy(t *testing.T, timeout *time.Duration, isFedramp bool, snykCodeApi string, orgId string) (*confMocks.MockConfig, *httpmocks.MockHTTPClient, *mocks.MockInstrumentor, *mocks.MockErrorReporter, *trackerMocks.MockTracker, *trackerMocks.MockTrackerFactory, zerolog.Logger) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes().Return("test-trace-id")
	mockSpan.EXPECT().Context().AnyTimes().Return(t.Context())
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().Organization().AnyTimes().Return(orgId)
	if snykCodeApi == "" {
		snykCodeApi = "http://localhost"
	}
	mockConfig.EXPECT().SnykCodeApi().AnyTimes().Return(snykCodeApi)
	mockConfig.EXPECT().IsFedramp().AnyTimes().Return(isFedramp)
	if timeout == nil {
		defaultTimeout := 120 * time.Second
		timeout = &defaultTimeout
	}
	mockConfig.EXPECT().SnykCodeAnalysisTimeout().AnyTimes().Return(*timeout)

	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)

	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
	mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
	mockTracker := trackerMocks.NewMockTracker(ctrl)
	mockTrackerFactory := trackerMocks.NewMockTrackerFactory(ctrl)
	mockTrackerFactory.EXPECT().GenerateTracker().Return(mockTracker).AnyTimes()

	logger := zerolog.Nop()
	return mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, mockTracker, mockTrackerFactory, logger
}

func TestAnalysis_RunLegacyTest_Success(t *testing.T) {
	bundleHash := "test-bundle-hash"
	shardKey := "test-shard-key"
	limitToFiles := []string{"file1.js", "file2.js"}
	severity := 2
	orgId := "test-org-id"

	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setupLegacy(t, nil, false, "", orgId)

	// Create expected sarif response
	sarifResponse := sarif.SarifResponse{
		Type:     "sarif",
		Progress: 1.0,
		Status:   analysis.StatusComplete,
		Sarif: sarif.SarifDocument{
			Version: "2.1.0",
			Runs: []sarif.Run{
				{
					Tool: sarif.Tool{
						Driver: sarif.Driver{
							Name:    "SnykCode",
							Version: "1.0.0",
						},
					},
					Results: []sarif.Result{},
				},
			},
		},
		Coverage: []sarif.SarifCoverage{
			{
				Files:       5,
				IsSupported: true,
				Lang:        "javascript",
			},
		},
		Timing: struct {
			FetchingCode int `json:"fetchingCode"`
			Queue        int `json:"queue"`
			Analysis     int `json:"analysis"`
		}{
			FetchingCode: 100,
			Analysis:     500,
		},
	}

	mockLegacyAnalysisResponse(t, mockHTTPClient, sarifResponse, bundleHash, orgId, http.StatusOK)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	result, status, err := analysisOrchestrator.RunLegacyTest(
		t.Context(),
		bundleHash,
		shardKey,
		limitToFiles,
		severity,
	)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, analysis.StatusComplete, status.Message)
	assert.Equal(t, 100, status.Percentage)
	assert.Equal(t, sarifResponse.Sarif.Version, result.Sarif.Version)
	assert.Equal(t, sarifResponse.Status, result.Status)
	assert.Equal(t, sarifResponse.Progress, result.Progress)
}

func TestAnalysis_RunLegacyTest_InProgress(t *testing.T) {
	bundleHash := "test-bundle-hash"
	shardKey := "test-shard-key"
	limitToFiles := []string{"file1.js"}
	severity := 1
	orgId := "test-org-id"

	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setupLegacy(t, nil, false, "", orgId)

	// Create expected sarif response for in-progress status
	sarifResponse := sarif.SarifResponse{
		Type:     "sarif",
		Progress: 0.6,
		Status:   analysis.StatusAnalyzing,
		Coverage: []sarif.SarifCoverage{},
		Timing: struct {
			FetchingCode int `json:"fetchingCode"`
			Queue        int `json:"queue"`
			Analysis     int `json:"analysis"`
		}{
			FetchingCode: 50,
			Analysis:     200,
		},
	}

	mockLegacyAnalysisResponse(t, mockHTTPClient, sarifResponse, bundleHash, orgId, http.StatusOK)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	result, status, err := analysisOrchestrator.RunLegacyTest(
		t.Context(),
		bundleHash,
		shardKey,
		limitToFiles,
		severity,
	)

	require.NoError(t, err)
	assert.Nil(t, result) // No result when not complete
	assert.Equal(t, analysis.StatusAnalyzing, status.Message)
	assert.Equal(t, 60, status.Percentage) // 0.6 * 100
}

func TestAnalysis_RunLegacyTest_Failed(t *testing.T) {
	bundleHash := "test-bundle-hash"
	shardKey := ""
	limitToFiles := []string{}
	severity := 0
	orgId := "test-org-id"

	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setupLegacy(t, nil, false, "", orgId)

	// Create expected sarif response for failed status
	sarifResponse := sarif.SarifResponse{
		Type:     "sarif",
		Progress: 0.0,
		Status:   analysis.StatusFailed,
	}

	mockLegacyAnalysisResponse(t, mockHTTPClient, sarifResponse, bundleHash, orgId, http.StatusOK)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	result, status, err := analysisOrchestrator.RunLegacyTest(
		t.Context(),
		bundleHash,
		shardKey,
		limitToFiles,
		severity,
	)

	require.Error(t, err)
	assert.IsType(t, analysis.FailedError{}, err)
	assert.Nil(t, result)
	assert.Equal(t, analysis.StatusFailed, status.Message)
}

func TestAnalysis_RunLegacyTest_EmptyStatus(t *testing.T) {
	bundleHash := "test-bundle-hash"
	shardKey := ""
	limitToFiles := []string{}
	severity := 0
	orgId := "test-org-id"

	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setupLegacy(t, nil, false, "", orgId)

	// Create expected sarif response with empty status
	sarifResponse := sarif.SarifResponse{
		Type:     "sarif",
		Progress: 0.0,
		Status:   "", // Empty status should be treated as error
	}

	mockLegacyAnalysisResponse(t, mockHTTPClient, sarifResponse, bundleHash, orgId, http.StatusOK)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	result, status, err := analysisOrchestrator.RunLegacyTest(
		t.Context(),
		bundleHash,
		shardKey,
		limitToFiles,
		severity,
	)

	require.Error(t, err)
	assert.IsType(t, analysis.FailedError{}, err)
	assert.Nil(t, result)
	assert.Equal(t, analysis.StatusFailed, status.Message)
}

func TestAnalysis_RunLegacyTest_HTTPError(t *testing.T) {
	bundleHash := "test-bundle-hash"
	shardKey := ""
	limitToFiles := []string{}
	severity := 0
	orgId := "test-org-id"

	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setupLegacy(t, nil, false, "", orgId)

	// Mock HTTP error response - need to check if the mock gives an error first
	expectedAnalysisUrl := "http://localhost/analysis"
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == expectedAnalysisUrl && req.Method == http.MethodPost
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusInternalServerError,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("Internal Server Error"))),
	}, nil) // No error from HTTP client, but bad status code

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	result, status, err := analysisOrchestrator.RunLegacyTest(
		t.Context(),
		bundleHash,
		shardKey,
		limitToFiles,
		severity,
	)

	require.Error(t, err)
	assert.IsType(t, analysis.FailedError{}, err)
	assert.Nil(t, result)
	assert.Equal(t, analysis.StatusFailed, status.Message)
}

func TestAnalysis_RunLegacyTest_Fedramp(t *testing.T) {
	bundleHash := "test-bundle-hash"
	shardKey := "test-shard-key"
	limitToFiles := []string{"file1.js"}
	severity := 2
	orgId := "test-org-id"

	// Test with fedramp configuration
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setupLegacy(t, nil, true, "https://deeproxy.snyk.io", orgId)

	// Create expected sarif response
	sarifResponse := sarif.SarifResponse{
		Type:     "sarif",
		Progress: 1.0,
		Status:   analysis.StatusComplete,
		Sarif: sarif.SarifDocument{
			Version: "2.1.0",
		},
	}

	// Expect the fedramp URL transformation
	expectedAnalysisUrl := fmt.Sprintf("https://api.snyk.io/hidden/orgs/%s/code/analysis", orgId)
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == expectedAnalysisUrl && req.Method == http.MethodPost
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(func() []byte {
			responseBodyBytes, _ := json.Marshal(sarifResponse)
			return responseBodyBytes
		}())),
	}, nil)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	result, status, err := analysisOrchestrator.RunLegacyTest(
		t.Context(),
		bundleHash,
		shardKey,
		limitToFiles,
		severity,
	)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, analysis.StatusComplete, status.Message)
	assert.Equal(t, 100, status.Percentage)
}

func TestAnalysis_RunLegacyTest_FedrampNoOrg(t *testing.T) {
	bundleHash := "test-bundle-hash"
	shardKey := ""
	limitToFiles := []string{}
	severity := 0
	orgId := "" // Empty org ID should cause error in fedramp

	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setupLegacy(t, nil, true, "https://deeproxy.snyk.io", orgId)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	result, status, err := analysisOrchestrator.RunLegacyTest(
		t.Context(),
		bundleHash,
		shardKey,
		limitToFiles,
		severity,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "organization is required in a fedramp environment")
	assert.Nil(t, result)
	assert.Equal(t, scan.LegacyScanStatus{}, status)
}

func TestAnalysis_RunLegacyTest_MalformedJSON(t *testing.T) {
	bundleHash := "test-bundle-hash"
	shardKey := ""
	limitToFiles := []string{}
	severity := 0
	orgId := "test-org-id"

	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setupLegacy(t, nil, false, "", orgId)

	// Mock response with malformed JSON
	expectedAnalysisUrl := "http://localhost/analysis"
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == expectedAnalysisUrl && req.Method == http.MethodPost
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte("invalid json{}"))),
	}, nil)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	result, status, err := analysisOrchestrator.RunLegacyTest(
		t.Context(),
		bundleHash,
		shardKey,
		limitToFiles,
		severity,
	)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Equal(t, analysis.StatusFailed, status.Message)
}

func TestFailedError_Error(t *testing.T) {
	err := analysis.FailedError{Msg: "test error message"}
	assert.Equal(t, "test error message", err.Error())
}

// TestHelperFunctions tests the unexported helper functions through reflection or by testing them indirectly
func TestAnalysis_CreateRequestBody(t *testing.T) {
	// Since createRequestBody is unexported, we test it indirectly by examining the request made in RunLegacyTest
	bundleHash := "test-bundle-hash"
	shardKey := "test-shard-key"
	limitToFiles := []string{"file1.js", "file2.js"}
	severity := 2
	orgId := "test-org-id"

	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setupLegacy(t, nil, false, "", orgId)

	var capturedRequestBody []byte
	expectedAnalysisUrl := "http://localhost/analysis"
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		if req.URL.String() == expectedAnalysisUrl && req.Method == http.MethodPost {
			// Capture the request body for validation
			body, _ := io.ReadAll(req.Body)
			capturedRequestBody = body
			// Reset the body for the actual request
			req.Body = io.NopCloser(bytes.NewReader(body))
			return true
		}
		return false
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"type":"sarif","progress":1.0,"status":"COMPLETE"}`))),
	}, nil)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	_, _, err := analysisOrchestrator.RunLegacyTest(
		scan.NewContextWithScanSource(t.Context(), scan.IDE),
		bundleHash,
		shardKey,
		limitToFiles,
		severity,
	)

	require.NoError(t, err)
	assert.NotEmpty(t, capturedRequestBody)

	// Parse and validate the request body structure
	var request map[string]interface{}
	err = json.Unmarshal(capturedRequestBody, &request)
	require.NoError(t, err)

	// Validate request structure
	assert.Equal(t, false, request["legacy"])
	assert.Contains(t, request, "key")
	assert.Contains(t, request, "severity")
	assert.Contains(t, request, "analysisContext")

	// Validate key structure
	key := request["key"].(map[string]interface{})
	assert.Equal(t, "file", key["type"])
	assert.Equal(t, bundleHash, key["hash"])
	assert.Equal(t, shardKey, key["shard"])

	// Validate limitToFiles
	limitToFilesInterface := key["limitToFiles"].([]interface{})
	assert.Len(t, limitToFilesInterface, 2)
	assert.Equal(t, "file1.js", limitToFilesInterface[0])
	assert.Equal(t, "file2.js", limitToFilesInterface[1])

	// Validate severity
	assert.Equal(t, float64(severity), request["severity"])

	// Validate analysisContext
	analysisContext := request["analysisContext"].(map[string]interface{})
	assert.Equal(t, string(scan.IDE), analysisContext["initiator"])
	assert.Equal(t, "language-server", analysisContext["flow"])

	org := analysisContext["org"].(map[string]interface{})
	assert.Equal(t, orgId, org["publicId"])
	assert.Equal(t, "unknown", org["name"])
	assert.Equal(t, "unknown", org["displayName"])
}

func TestAnalysis_CreateRequestBody_NoShardKey(t *testing.T) {
	bundleHash := "test-bundle-hash"
	shardKey := "" // Empty shard key
	limitToFiles := []string{}
	severity := 0
	orgId := "test-org-id"

	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setupLegacy(t, nil, false, "", orgId)

	var capturedRequestBody []byte
	expectedAnalysisUrl := "http://localhost/analysis"
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		if req.URL.String() == expectedAnalysisUrl && req.Method == http.MethodPost {
			body, _ := io.ReadAll(req.Body)
			capturedRequestBody = body
			req.Body = io.NopCloser(bytes.NewReader(body))
			return true
		}
		return false
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"type":"sarif","progress":1.0,"status":"COMPLETE"}`))),
	}, nil)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	_, _, err := analysisOrchestrator.RunLegacyTest(
		t.Context(),
		bundleHash,
		shardKey,
		limitToFiles,
		severity,
	)

	require.NoError(t, err)

	// Parse and validate the request body
	var request map[string]interface{}
	err = json.Unmarshal(capturedRequestBody, &request)
	require.NoError(t, err)

	key := request["key"].(map[string]interface{})
	// When shardKey is empty, it should still be included but as empty string (since shard field doesn't have omitempty)
	assert.Contains(t, key, "shard")
	assert.Equal(t, "", key["shard"])

	// When severity is 0, it should not be included in the request
	assert.NotContains(t, request, "severity")
}

func TestAnalysis_GetCodeApiUrl_Regular(t *testing.T) {
	// Test regular (non-fedramp) URL
	orgId := "test-org-id"
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setupLegacy(t, nil, false, "https://api.snyk.io", orgId)

	// We can't directly test getCodeApiUrl since it's unexported, but we can verify the URL used in requests
	expectedAnalysisUrl := "https://api.snyk.io/analysis"
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == expectedAnalysisUrl
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"type":"sarif","progress":1.0,"status":"COMPLETE"}`))),
	}, nil)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	_, _, err := analysisOrchestrator.RunLegacyTest(t.Context(), "hash", "", []string{}, 0)
	require.NoError(t, err)
}

func TestAnalysis_GetCodeApiUrl_Fedramp(t *testing.T) {
	// Test fedramp URL transformation
	orgId := "test-org-id"
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setupLegacy(t, nil, true, "https://deeproxy.snyk.io", orgId)

	// Verify the fedramp URL transformation: deeproxy -> api and adds org path
	expectedAnalysisUrl := fmt.Sprintf("https://api.snyk.io/hidden/orgs/%s/code/analysis", orgId)
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == expectedAnalysisUrl
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"type":"sarif","progress":1.0,"status":"COMPLETE"}`))),
	}, nil)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	_, _, err := analysisOrchestrator.RunLegacyTest(t.Context(), "hash", "", []string{}, 0)
	require.NoError(t, err)
}

func TestAnalysis_GetCodeApiUrl_InvalidURL(t *testing.T) {
	// Test with malformed URL in fedramp mode
	orgId := "test-org-id"
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setupLegacy(t, nil, true, ":::invalid-url", orgId)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	_, _, err := analysisOrchestrator.RunLegacyTest(t.Context(), "hash", "", []string{}, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
}
