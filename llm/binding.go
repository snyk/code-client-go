package llm

import (
	"context"
	"encoding/json"
	"net/url"
	"slices"

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
type ExplainResult []string

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

	unifiedDiffSuggestions = autofixResponse.toUnifiedDiffSuggestions(d.logger, options.BaseDir, options.FilePath)
	d.enrichWithExplain(span.Context(), options, unifiedDiffSuggestions)

	return unifiedDiffSuggestions, status, err
}

// enrichWithExplain fills in the Explanation for suggestions whose Autofix response did not
// already include one, falling back to the deprecated AI Explain service. Suggestions that
// already carry an explanation are left untouched, and the call is skipped entirely once none
// are missing or no ExplainEndpoint was configured.
func (d *DeepCodeLLMBindingImpl) enrichWithExplain(ctx context.Context, options AutofixOptions, suggestions []AutofixUnifiedDiffSuggestion) {
	method := "code.EnrichWithExplain"
	logger := d.logger.With().Str("method", method).Logger()

	missingIndices := make([]int, 0, len(suggestions))
	for i := range suggestions {
		if suggestions[i].Explanation == "" {
			missingIndices = append(missingIndices, i)
		}
	}
	if len(missingIndices) == 0 {
		return
	}

	if options.ExplainEndpoint == nil {
		logger.Debug().Msg("No ExplainEndpoint configured, skipping AI Explain fallback")
		return
	}

	span := d.instrumentor.StartSpan(ctx, method)
	defer d.instrumentor.Finish(span)

	diffs := make([]string, 0, len(missingIndices))
	for _, idx := range missingIndices {
		diffs = append(diffs, concatDiffs(suggestions[idx]))
	}

	response, err := d.runExplain(span.Context(), ExplainOptions{
		RuleKey:  options.RuleID,
		Diffs:    diffs,
		Endpoint: options.ExplainEndpoint,
	})
	if err != nil {
		logger.Err(err).Msg("Failed to obtain fallback explanations from AI Explain")
		return
	}

	explanations := getOrderedResponse(response)
	for i, idx := range missingIndices {
		if i >= len(explanations) {
			logger.Debug().Msgf("Failed to get fallback explanation for suggestion index %v", idx)
			break
		}
		suggestions[idx].Explanation = explanations[i]
	}
}

// concatDiffs concatenates the diffs of a suggestion across all its files, as the (deprecated)
// AI Explain service expects a single diff string per suggestion.
func concatDiffs(suggestion AutofixUnifiedDiffSuggestion) string {
	diff := ""
	for _, v := range suggestion.UnifiedDiffsPerFile {
		diff += v
	}
	return diff
}

func (d *DeepCodeLLMBindingImpl) ExplainWithOptions(ctx context.Context, options ExplainOptions) (ExplainResult, error) {
	s := d.instrumentor.StartSpan(ctx, "code.ExplainWithOptions")
	defer d.instrumentor.Finish(s)
	response, err := d.runExplain(s.Context(), options)
	explainResult := ExplainResult{}
	if err != nil {
		return explainResult, err
	}

	orderedExplainResults := getOrderedResponse(response)

	return orderedExplainResults, nil
}

func getOrderedResponse(explainResponse Explanations) []string {
	explainMapKeys := make([]string, 0, len(explainResponse))
	for k := range explainResponse {
		explainMapKeys = append(explainMapKeys, k)
	}
	slices.Sort(explainMapKeys)

	orderedValues := make([]string, 0, len(explainResponse))
	for _, key := range explainMapKeys {
		orderedValues = append(orderedValues, explainResponse[key])
	}
	return orderedValues
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
