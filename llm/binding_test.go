package llm

import (
	"net/http"
	"net/url"
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/observability"
	"github.com/stretchr/testify/assert"
)

func TestDeepcodeLLMBinding_PublishIssues(t *testing.T) {
	binding := NewDeepcodeLLMBinding()
	assert.PanicsWithValue(t, "implement me", func() { _ = binding.PublishIssues([]map[string]string{}) })
}

func TestDeepcodeLLMBinding_Explain(t *testing.T) {
	binding := NewDeepcodeLLMBinding()
	assert.PanicsWithValue(t, "implement me", func() { _ = binding.Explain("input", HTML, nil) })
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

func TestWithEndpoint(t *testing.T) {
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

			binding := &DeepcodeLLMBinding{}
			WithEndpoint(parsedURL)(binding)

			if binding.endpoint.Scheme != tc.expected.Scheme {
				t.Errorf("Expected Scheme: %s, Got: %s", tc.expected.Scheme, binding.endpoint.Scheme)
			}
			if binding.endpoint.Host != tc.expected.Host {
				t.Errorf("Expected Host: %s, Got: %s", tc.expected.Host, binding.endpoint.Host)
			}
			if binding.endpoint.Path != tc.expected.Path {
				t.Errorf("Expected Path: %s, Got: %s", tc.expected.Path, binding.endpoint.Path)
			}
			if binding.endpoint.RawQuery != tc.expected.RawQuery {
				t.Errorf("Expected RawQuery: %s, Got: %s", tc.expected.RawQuery, binding.endpoint.RawQuery)
			}

		})
	}
}

func TestWithInstrumentor(t *testing.T) {
	// Test case 1:  Provide a mock instrumentor
	mockInstrumentor := &MockInstrumentor{}
	binding := &DeepcodeLLMBinding{}

	WithInstrumentor(mockInstrumentor)(binding)

	assert.Equal(t, mockInstrumentor, binding.instrumentor)

	// Test case 2: Provide a nil instrumentor (should still set it)
	binding = &DeepcodeLLMBinding{} // Reset binding for the next test

	WithInstrumentor(nil)(binding)

	assert.Nil(t, binding.instrumentor)
}

// Mock Instrumentor (if you don't have a mock already)
type MockInstrumentor struct {
	observability.Instrumentor
}
