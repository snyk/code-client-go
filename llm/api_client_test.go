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
	"github.com/snyk/code-client-go/observability"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeepcodeLLMBinding_runExplain(t *testing.T) {
	tests := []struct {
		name               string
		options            explainOptions
		serverResponse     string
		serverStatusCode   int
		expectedResponse   explainResponse
		expectedError      string
		expectedLogMessage string
	}{
		{
			name: "successful vuln explanation",
			options: explainOptions{
				ruleKey:     "rule-key",
				derivation:  "derivation",
				ruleMessage: "rule-message",
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
			options: explainOptions{
				ruleKey: "rule-key",
				diff:    "diff",
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
			options:            explainOptions{}, // Missing required fields will cause an error
			serverStatusCode:   http.StatusUnprocessableEntity,
			expectedError:      "unexpected end of JSON input",
			expectedLogMessage: "error creating request body",
		},
		{
			name: "error getting response",
			options: explainOptions{
				ruleKey:     "rule-key",
				derivation:  "derivation",
				ruleMessage: "rule-message",
			},
			serverStatusCode:   http.StatusInternalServerError,
			expectedError:      "unexpected end of JSON input",
			expectedLogMessage: "error getting response",
		},
		{
			name: "error unmarshalling response",
			options: explainOptions{
				ruleKey:     "rule-key",
				derivation:  "derivation",
				ruleMessage: "rule-message",
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

			d := &DeepcodeLLMBinding{
				logger:       testLogger(t), // Replace with your logger implementation
				instrumentor: observability.NewInstrumentor(),
				endpoint:     u,
			}

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
		options := &explainOptions{
			ruleKey:     "test-rule-key",
			derivation:  "test-derivation",
			ruleMessage: "test-rule-message",
		}
		requestBody, err := d.explainRequestBody(options)
		require.NoError(t, err)

		var request explainRequest
		err = json.Unmarshal(requestBody, &request)
		require.NoError(t, err)

		assert.Nil(t, request.FixExplanation)
		assert.NotNil(t, request.VulnExplanation)
		assert.Equal(t, "test-rule-key", request.VulnExplanation.RuleId)
		assert.Equal(t, "test-derivation", request.VulnExplanation.Derivation)
		assert.Equal(t, "test-rule-message", request.VulnExplanation.RuleMessage)
		assert.Equal(t, SHORT, request.VulnExplanation.ExplanationLength)
	})

	t.Run("FixExplanation", func(t *testing.T) {
		options := &explainOptions{
			ruleKey: "test-rule-key",
			diff:    "test-diff",
		}
		requestBody, err := d.explainRequestBody(options)
		require.NoError(t, err)

		var request explainRequest
		err = json.Unmarshal(requestBody, &request)
		require.NoError(t, err)

		assert.Nil(t, request.VulnExplanation)
		assert.NotNil(t, request.FixExplanation)
		assert.Equal(t, "test-rule-key", request.FixExplanation.RuleId)
		assert.Equal(t, "test-diff", request.FixExplanation.Diff)
		assert.Equal(t, SHORT, request.FixExplanation.ExplanationLength)
	})

}

// Helper function for testing
func testLogger(t *testing.T) zerolog.Logger {
	t.Helper()
	return zerolog.New(io.Discard)
}
