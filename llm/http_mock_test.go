package llm_test

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/snyk/code-client-go/llm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeepcodeLLMBindingWithMockHTTP_ExplainWithOptions(t *testing.T) {
	testCases := []struct {
		name           string
		options        llm.ExplainOptions
		expectError    bool
		responseBody   []byte
		expectedResult llm.ExplainResult
		httpError      error
	}{
		{
			name: "success: fix explanation for multiple diffs",
			options: llm.ExplainOptions{
				RuleKey:  "rule-id",
				Diffs:    []string{"some diff 1", "some diff 2"},
				Endpoint: getExplainEndpoint(t),
			},
			expectError:  false,
			responseBody: []byte(`{"explanation": {"explanation1": "First explanation", "explanation2": "Second explanation"}}`),
			expectedResult: map[string]string{
				"some diff 1": "First explanation",
				"some diff 2": "Second explanation",
			},
		},
		{
			name: "failure: http error",
			options: llm.ExplainOptions{
				RuleKey:  "rule-id",
				Diffs:    []string{"some diff"},
				Endpoint: getExplainEndpoint(t),
			},
			expectError: true,
			httpError:   errors.New("connection error"),
		},
		{
			name: "failure: response unmarshal error",
			options: llm.ExplainOptions{
				RuleKey:  "rule-id",
				Diffs:    []string{"some diff"},
				Endpoint: getExplainEndpoint(t),
			},
			expectError:  true,
			responseBody: []byte(`{"invalid response json`),
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			// Set up mocked response
			mockHTTP := llm.NewMockHTTPClient()
			if testCase.httpError != nil {
				mockHTTP.Response.Error = testCase.httpError
			} else if testCase.responseBody != nil {
				mockHTTP.Response.Body = testCase.responseBody
			}

			binding := llm.NewDeepcodeLLMBinding(
				llm.WithMockHTTP(mockHTTP),
			)

			result, err := binding.ExplainWithOptions(context.Background(), testCase.options)

			if testCase.expectError {
				require.Error(t, err)
				if testCase.httpError != nil {
					assert.ErrorIs(t, err, testCase.httpError)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, testCase.expectedResult, result)
			}

			// Verify a request was made
			request := mockHTTP.GetLastRequest()
			require.NotNil(t, request)
		})
	}
}

// Helper function for testing
func getExplainEndpoint(t *testing.T) *url.URL {
	t.Helper()
	url, err := url.Parse("https://mock-url.com/some/path")
	assert.NoError(t, err)

	return url
}
