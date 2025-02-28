package llm

import (
	"context"
	"encoding/json"
	"io"
	http2 "net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/http/mocks"

	"github.com/snyk/code-client-go/observability"
)

func TestDeepcodeLLMBinding_PublishIssues(t *testing.T) {
	binding := NewDeepcodeLLMBinding()
	assert.PanicsWithValue(t, "implement me", func() { _ = binding.PublishIssues(context.Background(), []map[string]string{}) })
}

func TestExplainWithOptions(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		d, mockHTTPClient := getHTTPMockedBinding(t, &url.URL{Scheme: "http", Host: "test.com"})

		explainResponseJSON := explainResponse{
			Status:      completeStatus,
			Explanation: map[string]string{"explanation1": "This is the first explanation"},
		}

		expectedResponseBody, err := json.Marshal(explainResponseJSON)
		assert.NoError(t, err)
		mockResponse := http2.Response{
			Status:     "200 Ok",
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(string(expectedResponseBody))),
		}
		mockHTTPClient.EXPECT().Do(gomock.Any()).Return(&mockResponse, nil)
		testDiff := "test diff"
		explanation, err := d.ExplainWithOptions(context.Background(), ExplainOptions{Diffs: []string{testDiff}})
		assert.NoError(t, err)
		var exptectedExplanationsResponse explainResponse
		err = json.Unmarshal(expectedResponseBody, &exptectedExplanationsResponse)
		assert.NoError(t, err)
		expectedResExplanations := exptectedExplanationsResponse.Explanation
		assert.Equal(t, expectedResExplanations["explanation1"], explanation[testDiff])
	})

	t.Run("runExplain error", func(t *testing.T) {

	})
}

func getHTTPMockedBinding(t *testing.T, endpoint *url.URL) (*DeepCodeLLMBindingImpl, *mocks.MockHTTPClient) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockHTTPClient := mocks.NewMockHTTPClient(ctrl)
	d := NewDeepcodeLLMBinding(
		WithHTTPClient(func() http.HTTPClient { return mockHTTPClient }),
		WithEndpoint(endpoint),
	)
	return d, mockHTTPClient
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

	assert.NotNil(t, binding.endpoint)
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

			binding := &DeepCodeLLMBindingImpl{}
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
	binding := &DeepCodeLLMBindingImpl{}

	instrumentor := observability.NewInstrumentor()
	WithInstrumentor(instrumentor)(binding)

	assert.Equal(t, instrumentor, binding.instrumentor)

	// Test case 2: Provide a nil instrumentor (should still set it)
	binding = &DeepCodeLLMBindingImpl{} // Reset binding for the next test

	WithInstrumentor(nil)(binding)

	assert.Nil(t, binding.instrumentor)
}
