package llm

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/observability"
)

func TestToUnifiedDiffSuggestions(t *testing.T) {
	t.Run("carries the explanation from the autofix response", func(t *testing.T) {
		baseDir := t.TempDir()
		filePath := "main.go"
		require.NoError(t, os.WriteFile(filepath.Join(baseDir, filePath), []byte("vulnerable\n"), 0600))

		logger := zerolog.Nop()
		response := AutofixResponse{
			Status: completeStatus,
			AutofixSuggestions: []autofixResponseSingleFix{
				{Id: "fix-1", Value: "fixed\n", Explanation: "explanation for fix-1"},
			},
		}

		suggestions := response.toUnifiedDiffSuggestions(&logger, baseDir, filePath)

		require.Len(t, suggestions, 1)
		assert.Equal(t, "fix-1", suggestions[0].FixId)
		assert.Equal(t, "explanation for fix-1", suggestions[0].Explanation)
		assert.NotEmpty(t, suggestions[0].UnifiedDiffsPerFile[filepath.Join(baseDir, filePath)])
	})
}

func TestNewDeepcodeLLMBinding(t *testing.T) {
	logger := zerolog.Nop()
	client := http.NewHTTPClient(http.NewDefaultClientFactory())

	binding := NewDeepcodeLLMBinding(
		WithHTTPClient(func() http.HTTPClient { return client }),
		WithLogger(&logger),
	)

	assert.Equal(t, &logger, binding.logger)
	assert.Equal(t, client, binding.httpClientFunc())
}

func TestNewDeepcodeLLMBinding_Defaults(t *testing.T) {
	binding := NewDeepcodeLLMBinding()

	assert.NotNil(t, binding.logger)
	assert.NotNil(t, binding.httpClientFunc)
	assert.NotNil(t, binding.instrumentor)
}

func TestWithHTTPClient(t *testing.T) {
	client := http.NewHTTPClient(http.NewDefaultClientFactory())
	binding := &DeepCodeLLMBindingImpl{}
	WithHTTPClient(func() http.HTTPClient { return client })(binding)
	assert.Equal(t, client, binding.httpClientFunc())
}

func TestWithLogger(t *testing.T) {
	logger := zerolog.Nop()
	binding := &DeepCodeLLMBindingImpl{}
	WithLogger(&logger)(binding)
	assert.Equal(t, &logger, binding.logger)
}

// Test OutputFormat constants
func TestOutputFormatConstants(t *testing.T) {
	assert.Equal(t, OutputFormat("html"), HTML)
	assert.Equal(t, OutputFormat("json"), JSON)
	assert.Equal(t, OutputFormat("md"), MarkDown)
}

func TestWithOutputFormat(t *testing.T) {
	binding := &DeepCodeLLMBindingImpl{}

	// Test setting valid output formats
	WithOutputFormat(JSON)(binding)
	assert.Equal(t, JSON, binding.outputFormat)

	WithOutputFormat(HTML)(binding)
	assert.Equal(t, HTML, binding.outputFormat)

	WithOutputFormat(MarkDown)(binding)
	assert.Equal(t, MarkDown, binding.outputFormat)

	invalidFormat := OutputFormat("invalid")
	WithOutputFormat(invalidFormat)(binding)
	assert.Equal(t, MarkDown, binding.outputFormat)
}

func TestWithInstrumentor(t *testing.T) {
	// Test case 1:  Provide a mock instrumentor
	binding := &DeepCodeLLMBindingImpl{}

	instrumentor := observability.NewInstrumentor()
	WithInstrumentor(instrumentor)(binding)

	assert.Equal(t, instrumentor, binding.instrumentor)

	// Test case 2: Provide a nil instrumentor (should still set it)
	binding = &DeepCodeLLMBindingImpl{} // Reset binding for the next test

	WithInstrumentor(nil)(binding)

	assert.Nil(t, binding.instrumentor)
}
