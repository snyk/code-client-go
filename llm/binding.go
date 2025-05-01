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
	Id       string   `json:"id"`
	Input    string   `json:"inputs"`
	Endpoint *url.URL `json:"endpoint"`
}

var _ DeepCodeLLMBinding = (*DeepCodeLLMBindingImpl)(nil)
var _ SnykLLMBindings = (*DeepCodeLLMBindingImpl)(nil)

type SnykLLMBindings interface {
	// PublishIssues sends issues to an LLM for further processing.
	// the map in the slice of issues map is a json representation of json key : value
	// In case of errors, they are returned
	PublishIssues(ctx context.Context, issues []map[string]string) error

	// Explain forwards an input and desired output format to an LLM to
	// receive an explanation. The implementation should alter the LLM
	// prompt to honor the output format, but is not required to enforce
	// the format. The results should be streamed into the given channel
	//
	// Parameters:
	// ctx - request context
	// input - the thing to be explained as a string
	// format - the requested outputFormat
	// output - a channel that can be used to stream the results
	Explain(ctx context.Context, input AIRequest, format OutputFormat, output chan<- string) error
}
type ExplainResult map[string]string

type DeepCodeLLMBinding interface {
	SnykLLMBindings
	ExplainWithOptions(ctx context.Context, options ExplainOptions) (ExplainResult, error)
	GetAutofixDiffs(ctx context.Context, baseDir string, options AutofixOptions) (unifiedDiffSuggestions []AutofixUnifiedDiffSuggestion, status AutofixStatus, err error)
	SubmitAutofixFeedback(ctx context.Context, requestId string, options AutofixFeedbackOptions) error
}

// DeepCodeLLMBindingImpl is an LLM binding for the Snyk Code LLM.
type DeepCodeLLMBindingImpl struct {
	httpClientFunc func() http.HTTPClient
	logger         *zerolog.Logger
	outputFormat   OutputFormat
	instrumentor   observability.Instrumentor
}

func (d *DeepCodeLLMBindingImpl) SubmitAutofixFeedback(ctx context.Context, requestId string, options AutofixFeedbackOptions) error {
	method := "SubmitAutofixFeedback"
	span := d.instrumentor.StartSpan(ctx, method)
	defer d.instrumentor.Finish(span)
	logger := d.logger.With().Str("method", method).Logger()
	logger.Info().Str("requestId", requestId).Msg("Started submitting autofix feedback")
	defer logger.Info().Str("requestId", requestId).Msg("Finished submitting autofix feedback")

	err := d.submitAutofixFeedback(ctx, requestId, options)
	return err
}

func (d *DeepCodeLLMBindingImpl) GetAutofixDiffs(ctx context.Context, requestId string, options AutofixOptions) (unifiedDiffSuggestions []AutofixUnifiedDiffSuggestion, status AutofixStatus, err error) {
	method := "GetAutofixDiffs"
	span := d.instrumentor.StartSpan(ctx, method)
	defer d.instrumentor.Finish(span)
	logger := d.logger.With().Str("method", method).Logger()
	logger.Info().Str("requestId", requestId).Msg("Started obtaining autofix diffs")
	defer logger.Info().Str("requestId", requestId).Msg("Finished obtaining autofix diffs")

	autofixResponse, status, err := d.runAutofix(ctx, requestId, options)
	if err != nil {
		return nil, status, err
	}
	return autofixResponse.toUnifiedDiffSuggestions(d.logger, options.BaseDir, options.FilePath), status, err
}

func (d *DeepCodeLLMBindingImpl) ExplainWithOptions(ctx context.Context, options ExplainOptions) (ExplainResult, error) {
	s := d.instrumentor.StartSpan(ctx, "code.ExplainWithOptions")
	defer d.instrumentor.Finish(s)
	response, err := d.runExplain(s.Context(), options)
	explainResult := ExplainResult{}
	if err != nil {
		return explainResult, err
	}
	index := 0
	for _, explanation := range response {
		if index < len(options.Diffs) {
			explainResult[options.Diffs[index]] = explanation
		}
		index++
	}

	return explainResult, nil
}

func (d *DeepCodeLLMBindingImpl) PublishIssues(_ context.Context, _ []map[string]string) error {
	panic("implement me")
}

func (d *DeepCodeLLMBindingImpl) Explain(ctx context.Context, input AIRequest, _ OutputFormat, output chan<- string) error {
	var options ExplainOptions
	err := json.Unmarshal([]byte(input.Input), &options)
	if err != nil {
		return err
	}
	response, err := d.ExplainWithOptions(ctx, options)
	if err != nil {
		return err
	}
	jsonBytes, err := json.Marshal(response)
	if err != nil {
		return err
	}
	output <- string(jsonBytes)
	return nil
}

func NewDeepcodeLLMBinding(opts ...Option) *DeepCodeLLMBindingImpl {
	nopLogger := zerolog.Nop()
	binding := &DeepCodeLLMBindingImpl{
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
	}
	for _, opt := range opts {
		opt(binding)
	}
	return binding
}
