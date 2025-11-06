package llm

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/rs/zerolog"
	http2 "github.com/snyk/code-client-go/http"
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

			ctx := t.Context()
			ctx = observability.GetContextWithTraceId(ctx, "test-trace-id")

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
	req := &http.Request{Header: http.Header{"Existing-Header": {"existing-value"}}}

	http2.AddDefaultHeaders(req, http2.NoRequestId, "", http.MethodGet, false)

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

// Test with existing headers
func TestAddDefaultHeadersWithSkipEncodingEnabled(t *testing.T) {
	req := &http.Request{Header: http.Header{"Existing-Header": {"existing-value"}}}

	http2.AddDefaultHeaders(req, http2.NoRequestId, "", http.MethodPost, true)

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
