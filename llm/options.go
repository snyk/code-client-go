package llm

import (
	"net/url"

	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/observability"
)

type Option func(*DeepcodeLLMBinding)

func WithHTTPClient(httpClientFunc func() http.HTTPClient) func(*DeepcodeLLMBinding) {
	return func(binding *DeepcodeLLMBinding) {
		binding.httpClientFunc = httpClientFunc
	}
}

func WithEndpoint(endpoint *url.URL) func(*DeepcodeLLMBinding) {
	return func(binding *DeepcodeLLMBinding) {
		binding.endpoint = endpoint
	}
}

func WithLogger(logger *zerolog.Logger) func(*DeepcodeLLMBinding) {
	return func(binding *DeepcodeLLMBinding) {
		binding.logger = logger
	}
}

func WithOutputFormat(outputFormat OutputFormat) func(*DeepcodeLLMBinding) {
	return func(binding *DeepcodeLLMBinding) {
		if outputFormat != HTML && outputFormat != JSON && outputFormat != MarkDown {
			return
		}
		binding.outputFormat = outputFormat
	}
}

func WithInstrumentor(instrumentor observability.Instrumentor) func(*DeepcodeLLMBinding) {
	return func(binding *DeepcodeLLMBinding) {
		binding.instrumentor = instrumentor
	}
}
