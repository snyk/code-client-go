package llm

import (
	"context"

	"github.com/rs/zerolog"

	"github.com/snyk/code-client-go/http"

	"github.com/snyk/code-client-go/observability"
)

type OutputFormat string

const HTML OutputFormat = "html"
const JSON OutputFormat = "json"
const MarkDown OutputFormat = "md"

var _ DeepCodeLLMBinding = (*DeepCodeLLMBindingImpl)(nil)

type DeepCodeLLMBinding interface {
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

func (d *DeepCodeLLMBindingImpl) SubmitAutofixFeedback(ctx context.Context, fixId string, options AutofixFeedbackOptions) error {
	method := "SubmitAutofixFeedback"
	span := d.instrumentor.StartSpan(ctx, method)
	defer d.instrumentor.Finish(span)
	logger := d.logger.With().Str("method", method).Str("fixId", fixId).Logger()
	logger.Info().Msg("Started submitting autofix feedback")
	defer logger.Info().Msg("Finished submitting autofix feedback")

	err := d.submitAutofixFeedback(span.Context(), options)
	return err
}

func (d *DeepCodeLLMBindingImpl) GetAutofixDiffs(ctx context.Context, _ string, options AutofixOptions) (unifiedDiffSuggestions []AutofixUnifiedDiffSuggestion, status AutofixStatus, err error) {
	method := "GetAutofixDiffs"
	span := d.instrumentor.StartSpan(ctx, method)
	defer d.instrumentor.Finish(span)
	requestId := span.GetTraceId()
	logger := d.logger.With().Str("method", method).Str("requestId", requestId).Logger()
	logger.Info().Msg("Started obtaining autofix diffs")
	defer logger.Info().Msg("Finished obtaining autofix diffs")

	autofixResponse, status, err := d.runAutofix(span.Context(), options)
	if err != nil {
		return nil, status, err
	}
	return autofixResponse.toUnifiedDiffSuggestions(d.logger, options.BaseDir, options.FilePath), status, err
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
