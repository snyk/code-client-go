package llm

import (
	"net/http"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestDeepcodeLLMBinding_PublishIssues(t *testing.T) {
	binding := NewDeepcodeLLMBinding()
	assert.PanicsWithValue(t, "implement me", func() { binding.PublishIssues([]map[string]string{}) })
}

func TestDeepcodeLLMBinding_Explain(t *testing.T) {
	binding := NewDeepcodeLLMBinding()
	assert.PanicsWithValue(t, "implement me", func() { binding.Explain("input", HTML, nil) })
}

func TestNewDeepcodeLLMBinding(t *testing.T) {
	logger := zerolog.Nop()
	client := &http.Client{}
	output := make(chan<- string)

	binding := NewDeepcodeLLMBinding(
		WithHTTPClient(func() *http.Client { return client }),
		WithLogger(logger),
		WithOutputChannel(output),
	)

	assert.Equal(t, logger, binding.logger)
	assert.Equal(t, client, binding.httpClientFunc())
	assert.Equal(t, output, binding.outputChannel)
}

func TestNewDeepcodeLLMBinding_Defaults(t *testing.T) {
	binding := NewDeepcodeLLMBinding()

	assert.Equal(t, zerolog.Nop(), binding.logger)
	assert.Equal(t, http.DefaultClient, binding.httpClientFunc())
	assert.Nil(t, binding.outputChannel)
}

func TestWithHTTPClient(t *testing.T) {
	client := &http.Client{}
	binding := &DeepcodeLLMBinding{}
	WithHTTPClient(func() *http.Client { return client })(binding)
	assert.Equal(t, client, binding.httpClientFunc())
}

func TestWithLogger(t *testing.T) {
	logger := zerolog.Nop()
	binding := &DeepcodeLLMBinding{}
	WithLogger(logger)(binding)
	assert.Equal(t, logger, binding.logger)

}

func TestWithOutputChannel(t *testing.T) {
	output := make(chan<- string)
	binding := &DeepcodeLLMBinding{}
	WithOutputChannel(output)(binding)
	assert.Equal(t, output, binding.outputChannel)
}

// Test OutputFormat constants
func TestOutputFormatConstants(t *testing.T) {
	assert.Equal(t, OutputFormat("html"), HTML)
	assert.Equal(t, OutputFormat("json"), JSON)
	assert.Equal(t, OutputFormat("md"), MarkDown)
}

func TestWithOutputFormat(t *testing.T) {
	binding := &DeepcodeLLMBinding{}

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
