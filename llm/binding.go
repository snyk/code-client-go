package llm

import (
	"net/http"
	"net/url"

	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/observability"
)

type OutputFormat string

const HTML OutputFormat = "html"
const JSON OutputFormat = "json"
const MarkDown OutputFormat = "md"

type SnykLLMBindings interface {
	// PublishIssues sends issues to an LLM for further processing.
	// the map in the slice of issues map is a json representation of json key : value
	// In case of errors, they are returned
	PublishIssues(issues []map[string]string) error

	// Explain forwards an input and desired output format to an LLM to
	// receive an explanation. The implementation should alter the LLM
	// prompt to honor the output format, but is not required to enforce
	// the format. The results should be streamed into the given channel
	//
	// Parameters:
	// input - the thing to be explained as a string
	// format - the requested outputFormat
	// output - a channel that can be used to stream the results
	Explain(input string, format OutputFormat, output chan<- string) error
}

// DeepcodeLLMBinding is an LLM binding for the Snyk Code LLM.
// Currently, it only supports explain.
type DeepcodeLLMBinding struct {
	httpClientFunc func() *http.Client
	logger         zerolog.Logger
	outputChannel  chan<- string
	outputFormat   OutputFormat
	instrumentor   observability.Instrumentor
	endpoint       *url.URL
}

func (d *DeepcodeLLMBinding) PublishIssues(issues []map[string]string) error {
	panic("implement me")
}

func (d *DeepcodeLLMBinding) Explain(input string, format OutputFormat, output chan<- string) error {
	panic("implement me")
}

func NewDeepcodeLLMBinding(opts ...Option) *DeepcodeLLMBinding {
	endpoint, err := url.Parse(defaultEndpointURL)
	if err != nil {
		// time to panic, as our default should never be invalid
		panic(err)
	}

	binding := &DeepcodeLLMBinding{
		logger: zerolog.Nop(),
		httpClientFunc: func() *http.Client {
			return http.DefaultClient
		},
		outputChannel: nil,
		outputFormat:  MarkDown,
		instrumentor:  observability.NewInstrumentor(),
		endpoint:      endpoint,
	}
	for _, opt := range opts {
		opt(binding)
	}
	return binding
}
