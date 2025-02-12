package llm

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/http"

	"github.com/snyk/code-client-go/observability"
)

type OutputFormat string

const HTML OutputFormat = "html"
const JSON OutputFormat = "json"
const MarkDown OutputFormat = "md"

type AIRequest struct {
	Id    string `json:"id"`
	Input string `json:"inputs"`
}

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
	Explain(input AIRequest, format OutputFormat, output chan<- string) error
}

type DeepCodeLLMBinding interface {
	SnykLLMBindings
	ExplainWithOptions(options ExplainOptions) (string, error)
}

// DeepcodeLLMBinding is an LLM binding for the Snyk Code LLM.
// Currently, it only supports explain.
type DeepcodeLLMBinding struct {
	httpClientFunc func() http.HTTPClient
	logger         *zerolog.Logger
	outputFormat   OutputFormat
	instrumentor   observability.Instrumentor
	endpoint       *url.URL
}

func (d *DeepcodeLLMBinding) ExplainWithOptions(options ExplainOptions) (string, error) {
	s := d.instrumentor.StartSpan(context.Background(), "code.ExplainWithOptions")
	defer d.instrumentor.Finish(s)
	response, err := d.runExplain(s.Context(), options)
	if err != nil {
		return "", err
	}

	return response.Explanation, nil
}

func (d *DeepcodeLLMBinding) PublishIssues(issues []map[string]string) error {
	panic("implement me")
}

func (d *DeepcodeLLMBinding) Explain(input string, format OutputFormat, output chan<- string) error {
	var options ExplainOptions
	err := json.Unmarshal([]byte(input), &options)
	if err != nil {
		return err
	}
	response, err := d.ExplainWithOptions(options)
	if err != nil {
		return err
	}
	output <- response
	return nil
}

func NewDeepcodeLLMBinding(opts ...Option) *DeepcodeLLMBinding {
	endpoint, err := url.Parse(defaultEndpointURL)
	if err != nil {
		// time to panic, as our default should never be invalid
		panic(err)
	}

	nopLogger := zerolog.Nop()
	binding := &DeepcodeLLMBinding{
		logger: &nopLogger,
		httpClientFunc: func() http.HTTPClient {
			return http.NewHTTPClient(
				http.NewDefaultClientFactory(),
				http.WithRetryCount(3),
				http.WithLogger(&nopLogger),
			)
		},
		outputFormat: MarkDown,
		instrumentor: observability.NewInstrumentor(),
		endpoint:     endpoint,
	}
	for _, opt := range opts {
		opt(binding)
	}
	return binding
}
