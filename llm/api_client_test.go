package llm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/observability"
)

func TestDeepcodeLLMBinding_runExplain(t *testing.T) {
	tests := []struct {
		name               string
		options            ExplainOptions
		serverResponse     string
		serverStatusCode   int
		expectedResponse   Explanations
		expectedError      string
		expectedLogMessage string
	}{
		{
			name: "successful vuln explanation",
			options: ExplainOptions{
				RuleKey:     "rule-key",
				Derivation:  "Derivation",
				RuleMessage: "rule-message",
			},
			serverResponse:   "{\n    \"explanation\": \n        {\n            \"explanation1\": \"This is the first explanation\",\n            \"explanation2\": \"this is the second explanation\"\n                    }\n}",
			serverStatusCode: http.StatusOK,
			expectedResponse: map[string]string{"explanation1": "This is the first explanation", "explanation2": "this is the second explanation"},
		},
		{
			name: "successful fix explanation",
			options: ExplainOptions{
				RuleKey: "rule-key",
				Diffs:   []string{"Diffs"},
			},
			serverResponse:   "{\n    \"explanation\": \n        {\n            \"explanation1\": \"This is the first explanation\",\n            \"explanation2\": \"this is the second explanation\"\n                    }\n}",
			serverStatusCode: http.StatusOK,
			expectedResponse: map[string]string{"explanation1": "This is the first explanation", "explanation2": "this is the second explanation"},
		},
		{
			name:               "error creating request body",
			options:            ExplainOptions{}, // Missing required fields will cause an error
			serverStatusCode:   http.StatusUnprocessableEntity,
			expectedError:      "unexpected end of JSON input",
			expectedLogMessage: "error creating request body",
		},
		{
			name: "error getting response",
			options: ExplainOptions{
				RuleKey:     "rule-key",
				Derivation:  "Derivation",
				RuleMessage: "rule-message",
			},
			serverStatusCode:   http.StatusInternalServerError,
			expectedError:      "unexpected end of JSON input",
			expectedLogMessage: "error getting response",
		},
		{
			name: "error unmarshalling response",
			options: ExplainOptions{
				RuleKey:     "rule-key",
				Derivation:  "Derivation",
				RuleMessage: "rule-message",
			},
			serverResponse:     `invalid json`,
			serverStatusCode:   http.StatusOK,
			expectedError:      "invalid character 'i' looking for beginning of value",
			expectedLogMessage: "error unmarshalling",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.serverStatusCode)
				_, _ = w.Write([]byte(tt.serverResponse))
				if tt.expectedError == "unexpected EOF" {
					_ = r.Body.Close() // Close the request body early to simulate a read error
				}
			}))
			defer server.Close()

			u, err := url.Parse(server.URL)
			assert.NoError(t, err)
			tt.options.Endpoint = u

			d := NewDeepcodeLLMBinding()

			ctx := observability.GetContextWithTraceId(context.Background(), "test-trace-id")
			response, err := d.runExplain(ctx, tt.options)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResponse, response)
			}
		})
	}
}

func TestDeepcodeLLMBinding_explainRequestBody(t *testing.T) {
	d := &DeepCodeLLMBindingImpl{
		logger: testLogger(t),
	}

	t.Run("VulnExplanation", func(t *testing.T) {
		options := &ExplainOptions{
			RuleKey:     "test-rule-key",
			Derivation:  "test-Derivation",
			RuleMessage: "test-rule-message",
		}
		requestBody, err := d.explainRequestBody(options)
		require.NoError(t, err)

		var request explainVulnerabilityRequest
		err = json.Unmarshal(requestBody, &request)
		require.NoError(t, err)

		assert.NotNil(t, request)
		assert.Equal(t, "test-rule-key", request.RuleId)
		assert.Equal(t, "test-Derivation", request.Derivation)
		assert.Equal(t, "test-rule-message", request.RuleMessage)
		assert.Equal(t, SHORT, request.ExplanationLength)
	})

	t.Run("FixExplanation", func(t *testing.T) {
		options := &ExplainOptions{
			RuleKey: "test-rule-key",
			Diffs:   []string{"test-Diffs"},
		}
		requestBody, err := d.explainRequestBody(options)
		require.NoError(t, err)

		var request explainFixRequest
		err = json.Unmarshal(requestBody, &request)
		require.NoError(t, err)

		assert.NotNil(t, request)
		assert.Equal(t, "test-rule-key", request.RuleId)
		expectedEncodedDiffs := prepareDiffs([]string{"test-Diffs"})
		assert.Equal(t, expectedEncodedDiffs, request.Diffs)
		assert.Equal(t, SHORT, request.ExplanationLength)
	})
}

func TestEndpoint(t *testing.T) {
	testCases := []struct {
		name     string
		inputURL string
		expected url.URL
	}{
		{
			name:     "Valid URL",
			inputURL: "http://localhost:8080",
			expected: url.URL{Scheme: "http", Host: "localhost:8080"},
		},
		{
			name:     "URL with Path",
			inputURL: "https://example.com/path/to/resource",
			expected: url.URL{Scheme: "https", Host: "example.com", Path: "/path/to/resource"},
		},
		{
			name:     "URL with Query Params",
			inputURL: "http://api.example.com?param1=value1&param2=value2",
			expected: url.URL{Scheme: "http", Host: "api.example.com", RawQuery: "param1=value1&param2=value2"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			parsedURL, err := url.Parse(tc.inputURL)
			if err != nil {
				t.Fatalf("Failed to parse URL: %v", err)
			}

			options := &ExplainOptions{}
			options.Endpoint = parsedURL

			if options.Endpoint.Scheme != tc.expected.Scheme {
				t.Errorf("Expected Scheme: %s, Got: %s", tc.expected.Scheme, options.Endpoint.Scheme)
			}
			if options.Endpoint.Host != tc.expected.Host {
				t.Errorf("Expected Host: %s, Got: %s", tc.expected.Host, options.Endpoint.Host)
			}
			if options.Endpoint.Path != tc.expected.Path {
				t.Errorf("Expected Path: %s, Got: %s", tc.expected.Path, options.Endpoint.Path)
			}
			if options.Endpoint.RawQuery != tc.expected.RawQuery {
				t.Errorf("Expected RawQuery: %s, Got: %s", tc.expected.RawQuery, options.Endpoint.RawQuery)
			}
		})
	}
}

func TestPrepareDiffs(t *testing.T) {
	testCases := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name: "Single diff with headers and content",
			input: []string{
				"--- a/file.txt\n" +
					"+++ b/file.txt\n" +
					"@@ -1,1 +1,1 @@\n" +
					"-old line\n" +
					"+new line\n",
			},
			expected: []string{
				base64.StdEncoding.EncodeToString([]byte("@@ -1,1 +1,1 @@\n-old line\n+new line\n\n")),
			},
		},
		{
			name: "Multiple diffs",
			input: []string{
				"--- a/file1.txt\n" +
					"+++ b/file1.txt\n" +
					"-line 1\n" +
					"+line 2\n",
				"--- a/file2.txt\n" +
					"+++ b/file2.txt\n" +
					"content2a\n" +
					"+content2b\n",
			},
			expected: []string{
				base64.StdEncoding.EncodeToString([]byte("-line 1\n+line 2\n\n")),
				base64.StdEncoding.EncodeToString([]byte("content2a\n+content2b\n\n")),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := prepareDiffs(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

// Helper function for testing
func testLogger(t *testing.T) *zerolog.Logger {
	t.Helper()
	logger := zerolog.New(io.Discard)
	return &logger
}

// Test with existing headers
func TestAddDefaultHeadersWithExistingHeaders(t *testing.T) {
	d := &DeepCodeLLMBindingImpl{} // Initialize your struct if needed
	req := &http.Request{Header: http.Header{"Existing-Header": []string{"existing-value"}}}

	d.addDefaultHeaders(req, "", "")

	cacheControl := req.Header.Get("Cache-Control")
	contentType := req.Header.Get("Content-Type")
	existingHeader := req.Header.Get("Existing-Header")

	if cacheControl != "private, max-age=0, no-cache" {
		t.Errorf("Expected Cache-Control header to be 'private, max-age=0, no-cache', got %s", cacheControl)
	}

	if contentType != "application/json" {
		t.Errorf("Expected Content-Type header to be 'application/json', got %s", contentType)
	}

	if existingHeader != "existing-value" {
		t.Errorf("Expected Existing-Header to be 'existing-value', got %s", existingHeader)
	}
}

func TestAddDefaultHeadersWithRequestIdAndOrgId(t *testing.T) {
	d := &DeepCodeLLMBindingImpl{}
	req := &http.Request{Header: http.Header{}}

	testRequestId := "test-request-id-123"
	testOrgId := "test-org-id-456"

	d.addDefaultHeaders(req, testRequestId, testOrgId)

	snykRequestId := req.Header.Get("snyk-request-id")
	snykOrgName := req.Header.Get("snyk-org-name")
	cacheControl := req.Header.Get("Cache-Control")
	contentType := req.Header.Get("Content-Type")

	if snykRequestId != testRequestId {
		t.Errorf("Expected snyk-request-id header to be '%s', got '%s'", testRequestId, snykRequestId)
	}

	if snykOrgName != testOrgId {
		t.Errorf("Expected snyk-org-name header to be '%s', got '%s'", testOrgId, snykOrgName)
	}

	if cacheControl != "private, max-age=0, no-cache" {
		t.Errorf("Expected Cache-Control header to be 'private, max-age=0, no-cache', got %s", cacheControl)
	}

	if contentType != "application/json" {
		t.Errorf("Expected Content-Type header to be 'application/json', got %s", contentType)
	}
}

func TestAddDefaultHeadersWithRequestIdOnly(t *testing.T) {
	d := &DeepCodeLLMBindingImpl{}
	req := &http.Request{Header: http.Header{}}

	testRequestId := "test-request-id-789"

	d.addDefaultHeaders(req, testRequestId, "")

	snykRequestId := req.Header.Get("snyk-request-id")
	snykOrgName := req.Header.Get("snyk-org-name")

	if snykRequestId != testRequestId {
		t.Errorf("Expected snyk-request-id header to be '%s', got '%s'", testRequestId, snykRequestId)
	}

	if snykOrgName != "" {
		t.Errorf("Expected snyk-org-name header to be empty, got '%s'", snykOrgName)
	}
}

func TestAddDefaultHeadersWithOrgIdOnly(t *testing.T) {
	d := &DeepCodeLLMBindingImpl{}
	req := &http.Request{Header: http.Header{}}

	testOrgId := "test-org-id-999"

	d.addDefaultHeaders(req, "", testOrgId)

	snykRequestId := req.Header.Get("snyk-request-id")
	snykOrgName := req.Header.Get("snyk-org-name")

	if snykRequestId != "" {
		t.Errorf("Expected snyk-request-id header to be empty, got '%s'", snykRequestId)
	}

	if snykOrgName != testOrgId {
		t.Errorf("Expected snyk-org-name header to be '%s', got '%s'", testOrgId, snykOrgName)
	}
}

func TestAddDefaultHeadersWithEmptyParameters(t *testing.T) {
	d := &DeepCodeLLMBindingImpl{}
	req := &http.Request{Header: http.Header{}}

	d.addDefaultHeaders(req, "", "")

	snykRequestId := req.Header.Get("snyk-request-id")
	snykOrgName := req.Header.Get("snyk-org-name")
	cacheControl := req.Header.Get("Cache-Control")
	contentType := req.Header.Get("Content-Type")

	if snykRequestId != "" {
		t.Errorf("Expected snyk-request-id header to be empty, got '%s'", snykRequestId)
	}

	if snykOrgName != "" {
		t.Errorf("Expected snyk-org-name header to be empty, got '%s'", snykOrgName)
	}

	if cacheControl != "private, max-age=0, no-cache" {
		t.Errorf("Expected Cache-Control header to be 'private, max-age=0, no-cache', got %s", cacheControl)
	}

	if contentType != "application/json" {
		t.Errorf("Expected Content-Type header to be 'application/json', got %s", contentType)
	}
}

func TestE2E_HTTPHeadersSentToServer(t *testing.T) {
	// Capture headers sent to the server
	var capturedHeaders http.Header
	var requestCount int

	// Create test server that captures headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		capturedHeaders = r.Header.Clone()

		w.WriteHeader(http.StatusOK)
		response := AutofixResponse{
			Status: "COMPLETE",
			AutofixSuggestions: []autofixResponseSingleFix{
				{
					Id:    "test-fix-id",
					Value: "test-unified-diff",
				},
			},
		}
		responseBytes, _ := json.Marshal(response)
		_, _ = w.Write(responseBytes)
	}))
	defer server.Close()

	// Create test context with trace ID (which becomes the request ID)
	testTraceId := "test-trace-id-e2e-123"
	ctx := observability.GetContextWithTraceId(context.Background(), testTraceId)

	// Create AutofixOptions with org ID
	testOrgId := "test-org-public-id-456"
	options := AutofixOptions{
		RuleID:     "test-rule-id",
		BundleHash: "test-bundle-hash",
		ShardKey:   "test-shard-key",
		BaseDir:    "/test/base/dir",
		FilePath:   "/test/file.js",
		LineNum:    10,
		Host:       server.URL, // Use test server URL
		CodeRequestContext: CodeRequestContext{
			Initiator: "test",
			Flow:      "test-flow",
			Org: CodeRequestContextOrg{
				Name:        "test-org",
				DisplayName: "Test Organization",
				PublicId:    testOrgId,
				Flags:       map[string]bool{},
			},
		},
		IdeExtensionDetails: AutofixIdeExtensionDetails{
			ExtensionName:    "test-extension",
			ExtensionVersion: "1.0.0",
			IdeName:          "test-ide",
			IdeVersion:       "1.0.0",
		},
	}

	// Create binding instance
	binding := NewDeepcodeLLMBinding()

	// Make the actual HTTP request
	_, status, err := binding.runAutofix(ctx, options)

	// Verify the request was successful
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", status.Message)
	assert.Equal(t, 1, requestCount, "Expected exactly one HTTP request to be made")

	// Verify the expected headers were sent
	t.Run("VerifySnykRequestIdHeader", func(t *testing.T) {
		actualRequestId := capturedHeaders.Get("snyk-request-id")
		assert.Equal(t, testTraceId, actualRequestId, "snyk-request-id header should match the trace ID")
	})

	t.Run("VerifySnykOrgNameHeader", func(t *testing.T) {
		actualOrgId := capturedHeaders.Get("snyk-org-name")
		assert.Equal(t, testOrgId, actualOrgId, "snyk-org-name header should match the org public ID")
	})

	t.Run("VerifyStandardHeaders", func(t *testing.T) {
		contentType := capturedHeaders.Get("Content-Type")
		cacheControl := capturedHeaders.Get("Cache-Control")

		assert.Equal(t, "application/json", contentType, "Content-Type header should be set")
		assert.Equal(t, "private, max-age=0, no-cache", cacheControl, "Cache-Control header should be set")
	})
}

func TestE2E_GetAutofixDiffsHTTPHeadersSentToServer(t *testing.T) {
	// Capture headers sent to the server
	var capturedHeaders http.Header
	var requestCount int

	// Create test server that captures headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		capturedHeaders = r.Header.Clone()

		// Return a valid autofix response
		w.WriteHeader(http.StatusOK)
		response := AutofixResponse{
			Status: "COMPLETE",
			AutofixSuggestions: []autofixResponseSingleFix{
				{
					Id:    "test-fix-id-get-diffs",
					Value: "diff --git a/test.js b/test.js\n--- a/test.js\n+++ b/test.js\n@@ -1,1 +1,1 @@\n-var x = 1;\n+const x = 1;",
				},
			},
		}
		responseBytes, _ := json.Marshal(response)
		_, _ = w.Write(responseBytes)
	}))
	defer server.Close()

	// Create test context with trace ID
	testTraceId := "test-get-autofix-diffs-trace-id-999"
	ctx := observability.GetContextWithTraceId(context.Background(), testTraceId)

	// Create AutofixOptions with org ID
	testOrgId := "test-org-public-id-789"
	options := AutofixOptions{
		RuleID:     "test-rule-id-diffs",
		BundleHash: "test-bundle-hash-diffs",
		ShardKey:   "test-shard-key-diffs",
		BaseDir:    "/test/base/dir/diffs",
		FilePath:   "/test/file-diffs.js",
		LineNum:    25,
		Host:       server.URL, // Use test server URL
		CodeRequestContext: CodeRequestContext{
			Initiator: "test-diffs",
			Flow:      "test-flow-diffs",
			Org: CodeRequestContextOrg{
				Name:        "test-org-diffs",
				DisplayName: "Test Organization Diffs",
				PublicId:    testOrgId,
				Flags:       map[string]bool{},
			},
		},
		IdeExtensionDetails: AutofixIdeExtensionDetails{
			ExtensionName:    "test-extension-diffs",
			ExtensionVersion: "2.0.0",
			IdeName:          "test-ide-diffs",
			IdeVersion:       "2.0.0",
		},
	}

	// Create binding instance
	binding := NewDeepcodeLLMBinding()

	// Make the actual HTTP request using GetAutofixDiffs
	_, status, err := binding.GetAutofixDiffs(ctx, "ignored-fix-id", options)

	// Verify the request was successful (note: diffs may be empty due to file not existing)
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", status.Message)
	// Note: diffs will be empty because the test file paths don't exist on disk
	// This is expected behavior - we're primarily testing headers, not file operations
	assert.Equal(t, 1, requestCount, "Expected exactly one HTTP request to be made")

	// Verify the expected headers were sent
	t.Run("VerifySnykRequestIdHeaderInGetAutofixDiffs", func(t *testing.T) {
		actualRequestId := capturedHeaders.Get("snyk-request-id")
		assert.Equal(t, testTraceId, actualRequestId, "snyk-request-id header should match the trace ID")
	})

	t.Run("VerifySnykOrgNameHeaderInGetAutofixDiffs", func(t *testing.T) {
		actualOrgId := capturedHeaders.Get("snyk-org-name")
		assert.Equal(t, testOrgId, actualOrgId, "snyk-org-name header should match the org public ID")
	})

	t.Run("VerifyStandardHeadersInGetAutofixDiffs", func(t *testing.T) {
		contentType := capturedHeaders.Get("Content-Type")
		cacheControl := capturedHeaders.Get("Cache-Control")

		assert.Equal(t, "application/json", contentType, "Content-Type header should be set")
		assert.Equal(t, "private, max-age=0, no-cache", cacheControl, "Cache-Control header should be set")
	})
}

func TestAutofixRequestBody(t *testing.T) {
	d := &DeepCodeLLMBindingImpl{}

	const testBundleHash = "0123456789abcdef"
	const testBaseDir = "basedir"
	const testFilePath = "/path/to/file"
	const testLineNumber0Based = 0
	const testRuleId = "rule_id"
	const testShardKey = "shard_key"
	const testHost = "http://api.test.snyk.io"
	const testIdeName = "my IDE"
	const testIdeVersion = "1.0.0"
	const testExtensionName = "my extension"
	const testExtensionVersion = "1.2.3"

	options := AutofixOptions{
		RuleID:     testRuleId,
		BundleHash: testBundleHash,
		ShardKey:   testShardKey,
		Host:       testHost,
		BaseDir:    testBaseDir,
		FilePath:   testFilePath,
		LineNum:    testLineNumber0Based,
		CodeRequestContext: CodeRequestContext{
			Initiator: "",
			Flow:      "",
			Org:       CodeRequestContextOrg{},
		},
		IdeExtensionDetails: AutofixIdeExtensionDetails{
			IdeName:          testIdeName,
			IdeVersion:       testIdeVersion,
			ExtensionName:    testExtensionName,
			ExtensionVersion: testExtensionVersion,
		},
	}

	jsonBody, err := d.autofixRequestBody(&options)
	assert.NoError(t, err)

	expectedBody := AutofixRequest{
		Key: AutofixRequestKey{
			Type:     "file",
			Hash:     testBundleHash,
			Shard:    testShardKey,
			FilePath: testFilePath,
			RuleId:   testRuleId,
			LineNum:  testLineNumber0Based,
		},
		AnalysisContext: CodeRequestContext{
			Initiator: "",
			Flow:      "",
			Org:       CodeRequestContextOrg{},
		},
		IdeExtensionDetails: AutofixIdeExtensionDetails{
			IdeName:          testIdeName,
			IdeVersion:       testIdeVersion,
			ExtensionName:    testExtensionName,
			ExtensionVersion: testExtensionVersion,
		},
	}

	var body AutofixRequest
	err = json.Unmarshal(jsonBody, &body)
	assert.NoError(t, err)

	assert.Equal(t, expectedBody, body)
}
