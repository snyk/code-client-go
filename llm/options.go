package llm

import (
	"net/url"

	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/http"
	"github.com/snyk/code-client-go/observability"
)

type Option func(*DeepCodeLLMBindingImpl)

func WithHTTPClient(httpClientFunc func() http.HTTPClient) func(*DeepCodeLLMBindingImpl) {
	return func(binding *DeepCodeLLMBindingImpl) {
		binding.httpClientFunc = httpClientFunc
	}
}

func WithEndpoint(endpoint *url.URL) func(*DeepCodeLLMBindingImpl) {
	return func(binding *DeepCodeLLMBindingImpl) {
		binding.endpoint = endpoint
	}
}

func WithLogger(logger *zerolog.Logger) func(*DeepCodeLLMBindingImpl) {
	return func(binding *DeepCodeLLMBindingImpl) {
		binding.logger = logger
	}
}

func WithOutputFormat(outputFormat OutputFormat) func(*DeepCodeLLMBindingImpl) {
	return func(binding *DeepCodeLLMBindingImpl) {
		if outputFormat != HTML && outputFormat != JSON && outputFormat != MarkDown {
			return
		}
		binding.outputFormat = outputFormat
	}
}

func WithInstrumentor(instrumentor observability.Instrumentor) func(*DeepCodeLLMBindingImpl) {
	return func(binding *DeepCodeLLMBindingImpl) {
		binding.instrumentor = instrumentor
	}
}
