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
		d, mockHTTPClient := getHTTPMockedBinding(t)

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
		endpoint := &url.URL{Scheme: "http", Host: "test.com"}
		explanation, err := d.ExplainWithOptions(context.Background(), ExplainOptions{Diffs: []string{testDiff}, Endpoint: endpoint})
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

func getHTTPMockedBinding(t *testing.T) (*DeepCodeLLMBindingImpl, *mocks.MockHTTPClient) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockHTTPClient := mocks.NewMockHTTPClient(ctrl)
	d := NewDeepcodeLLMBinding(
		WithHTTPClient(func() http.HTTPClient { return mockHTTPClient }),
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
