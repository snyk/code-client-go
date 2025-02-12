package llm

import (
	"context"
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
		expectedResponse   explainResponse
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
			serverResponse:   `{"explanation": "This is a vulnerability explanation"}`,
			serverStatusCode: http.StatusOK,
			expectedResponse: explainResponse{
				Status:      completeStatus,
				Explanation: "This is a vulnerability explanation",
			},
		},
		{
			name: "successful fix explanation",
			options: ExplainOptions{
				RuleKey: "rule-key",
				Diff:    "Diff",
			},
			serverResponse:   `{"explanation": "This is a fix explanation"}`,
			serverStatusCode: http.StatusOK,
			expectedResponse: explainResponse{
				Status:      completeStatus,
				Explanation: "This is a fix explanation",
			},
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

			d := NewDeepcodeLLMBinding(WithEndpoint(u))

			ctx := context.Background()
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
	d := &DeepcodeLLMBinding{
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

		var request explainRequest
		err = json.Unmarshal(requestBody, &request)
		require.NoError(t, err)

		assert.Nil(t, request.FixExplanation)
		assert.NotNil(t, request.VulnExplanation)
		assert.Equal(t, "test-rule-key", request.VulnExplanation.RuleId)
		assert.Equal(t, "test-Derivation", request.VulnExplanation.Derivation)
		assert.Equal(t, "test-rule-message", request.VulnExplanation.RuleMessage)
		assert.Equal(t, SHORT, request.VulnExplanation.ExplanationLength)
	})

	t.Run("FixExplanation", func(t *testing.T) {
		options := &ExplainOptions{
			RuleKey: "test-rule-key",
			Diff:    "test-Diff",
		}
		requestBody, err := d.explainRequestBody(options)
		require.NoError(t, err)

		var request explainRequest
		err = json.Unmarshal(requestBody, &request)
		require.NoError(t, err)

		assert.Nil(t, request.VulnExplanation)
		assert.NotNil(t, request.FixExplanation)
		assert.Equal(t, "test-rule-key", request.FixExplanation.RuleId)
		assert.Equal(t, "test-Diff", request.FixExplanation.Diff)
		assert.Equal(t, SHORT, request.FixExplanation.ExplanationLength)
	})

}

// Helper function for testing
func testLogger(t *testing.T) *zerolog.Logger {
	t.Helper()
	logger := zerolog.New(io.Discard)
	return &logger
}

// Test with existing headers
func TestAddDefaultHeadersWithExistingHeaders(t *testing.T) {
	d := &DeepcodeLLMBinding{} // Initialize your struct if needed
	req := &http.Request{Header: http.Header{"Existing-Header": {"existing-value"}}}
	requestId := "test-request-id"

	d.addDefaultHeaders(req, requestId)

	snykRequestId := req.Header.Get("snyk-request-id")
	cacheControl := req.Header.Get("Cache-Control")
	contentType := req.Header.Get("Content-Type")
	existingHeader := req.Header.Get("Existing-Header")

	if snykRequestId != requestId {
		t.Errorf("Expected snyk-request-id header to be %s, got %s", requestId, snykRequestId)
	}

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
