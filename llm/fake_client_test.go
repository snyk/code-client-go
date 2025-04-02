package llm_test

import (
	"context"
	"testing"

	"github.com/snyk/code-client-go/llm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFakeDeepcodeLLMBinding_ExplainWithOptions(t *testing.T) {
	testCases := []struct {
		name             string
		options          llm.ExplainOptions
		expectedResponse llm.ExplainResult
		isExpectedError  bool
	}{
		{
			name: "success: fix explanation for single diff",
			options: llm.ExplainOptions{
				RuleKey: "rule-key",
				Diffs:   []string{"a single diff"},
			},
			expectedResponse: map[string]string{"explanation1": "This is the first explanation", "explanation2": ""},
		},
		{
			name: "success: fix explanation for multiple diffs",
			options: llm.ExplainOptions{
				RuleKey: "rule-key",
				Diffs:   []string{"a diff", "another diff"},
			},
			expectedResponse: map[string]string{"explanation1": "This is the first explanation", "explanation2": "this is the second explanation"},
		},
		{
			name: "fail: general error",
			options: llm.ExplainOptions{
				RuleKey: "rule-key",
				Diffs:   []string{"diff"},
			},
			expectedResponse: nil,
			isExpectedError:  true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			f := llm.NewFakeDeepcodeLLMBinding()
			f.IsServerErr = testCase.isExpectedError
			f.Result = testCase.expectedResponse

			response, err := f.ExplainWithOptions(context.Background(), testCase.options)

			if testCase.isExpectedError {
				require.Error(t, err)
				assert.Nil(t, response)
			} else {
				require.NoError(t, err)
				assert.Equal(t, testCase.expectedResponse, response)
			}
		})
	}
}
