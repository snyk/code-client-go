package llm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/snyk/code-client-go/internal/deepcode"
)

var (
	completeStatus     = "COMPLETE"
	defaultEndpointURL = "http://localhost:10000/explain"
)

func (d *DeepCodeLLMBindingImpl) runExplain(ctx context.Context, options ExplainOptions) (Explanations, error) {
	span := d.instrumentor.StartSpan(ctx, "code.RunExplain")
	defer span.Finish()

	logger := d.logger.With().Str("method", "code.RunExplain").Logger()

	logger.Debug().Msg("API: Retrieving explain for bundle")
	defer logger.Debug().Msg("API: Retrieving explain done")

	requestBody, err := d.explainRequestBody(&options)
	if err != nil {
		logger.Err(err).Str("requestBody", string(requestBody)).Msg("error creating request body")
		return Explanations{}, err
	}
	logger.Debug().Str("payload body: %s\n", string(requestBody)).Msg("Marshaled payload")

	u := options.Endpoint
	if u == nil {
		u, err = url.Parse(defaultEndpointURL)
		if err != nil {
			logger.Err(err).Send()
			return Explanations{}, err
		}
	}

	responseBody, err := d.submitRequest(span.Context(), u, requestBody, "")
	if err != nil {
		return Explanations{}, err
	}

	var response explainResponse
	var explains Explanations
	response.Status = completeStatus
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		logger.Err(err).Str("responseBody", string(responseBody)).Msg("error unmarshalling")
		return Explanations{}, err
	}

	explains = response.Explanation

	return explains, nil
}

func (d *DeepCodeLLMBindingImpl) submitRequest(ctx context.Context, url *url.URL, requestBody []byte, orgId string) ([]byte, error) {
	logger := d.logger.With().Str("method", "submitRequest").Logger()
	logger.Trace().Str("payload body: %s\n", string(requestBody)).Msg("Marshaled payload")
	span := d.instrumentor.StartSpan(ctx, "code.SubmitRequest")
	defer span.Finish()

	// Encode the request body
	bodyBuffer, err := deepcode.EncodeIfNeeded(http.MethodPost, requestBody)
	if err != nil {
		logger.Err(err).Str("requestBody", string(requestBody)).Msg("error encoding request body")
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url.String(), bodyBuffer)
	if err != nil {
		logger.Err(err).Str("requestBody", string(requestBody)).Msg("error creating request")
		return nil, err
	}

	deepcode.AddHeaders(http.MethodPost, req, orgId)

	resp, err := d.httpClientFunc().Do(req) //nolint:bodyclose // this seems to be a false positive
	if err != nil {
		logger.Err(err).Str("requestBody", string(requestBody)).Msg("error getting response")
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		bodyCloseErr := Body.Close()
		if bodyCloseErr != nil {
			logger.Err(err).Str("requestBody", string(requestBody)).Msg("error closing response")
		}
	}(resp.Body)

	// Read the response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Err(err).Str("requestBody", string(requestBody)).Msg("error reading all response")
		return nil, err
	}
	logger.Debug().Str("response body: %s\n", string(responseBody)).Msg("Got the response")

	return responseBody, nil
}

func (d *DeepCodeLLMBindingImpl) explainRequestBody(options *ExplainOptions) ([]byte, error) {
	logger := d.logger.With().Str("method", "code.explainRequestBody").Logger()

	var requestBody []byte
	var marshalErr error
	if len(options.Diffs) == 0 {
		requestBody, marshalErr = json.Marshal(explainVulnerabilityRequest{
			RuleId:            options.RuleKey,
			Derivation:        options.Derivation,
			RuleMessage:       options.RuleMessage,
			ExplanationLength: SHORT,
		})
		logger.Debug().Msg("payload for VulnExplanation")
	} else {
		requestBody, marshalErr = json.Marshal(explainFixRequest{
			RuleId:            options.RuleKey,
			Diffs:             prepareDiffs(options.Diffs),
			ExplanationLength: SHORT,
		})
		logger.Debug().Msg("payload for FixExplanation")
	}
	return requestBody, marshalErr
}

var failed = AutofixStatus{Message: "FAILED"}

func (d *DeepCodeLLMBindingImpl) runAutofix(ctx context.Context, options AutofixOptions) (AutofixResponse, AutofixStatus, error) {
	span := d.instrumentor.StartSpan(ctx, "code.RunAutofix")
	defer span.Finish()

	logger := d.logger.With().Str("method", "code.RunAutofix").Str("requestId", span.GetTraceId()).Logger()

	endpoint, err := url.Parse(fmt.Sprintf("%s/autofix/suggestions", options.Host))
	if err != nil {
		logger.Err(err).Str("host", options.Host).Msg("error creating endpoint URL")
		return AutofixResponse{}, failed, err
	}

	requestBody, err := d.autofixRequestBody(&options)
	if err != nil {
		logger.Err(err).Str("requestBody", string(requestBody)).Msg("error creating request body")
		return AutofixResponse{}, failed, err
	}

	logger.Info().Msg("Started obtaining autofix Response")
	responseBody, err := d.submitRequest(span.Context(), endpoint, requestBody, options.CodeRequestContext.Org.PublicId)
	logger.Info().Msg("Finished obtaining autofix Response")

	if err != nil {
		logger.Err(err).Str("responseBody", string(responseBody)).Msg("error response from autofix")
		return AutofixResponse{}, failed, err
	}

	var response AutofixResponse
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		logger.Err(err).Str("responseBody", string(responseBody)).Msg("error unmarshalling")
		return AutofixResponse{}, failed, err
	}

	logger.Debug().Msgf("Status: %s", response.Status)

	if response.Status == failed.Message {
		errMsg := "autofix failed"
		logger.Error().Str("responseStatus", response.Status).Msg(errMsg)
		return response, failed, errors.New(errMsg)
	}

	if response.Status == "" {
		errMsg := "unknown response status (empty)"
		logger.Error().Str("responseStatus", response.Status).Msg(errMsg)
		return response, failed, errors.New(errMsg)
	}

	status := AutofixStatus{Message: response.Status}
	if response.Status != completeStatus {
		return response, status, nil
	}

	return response, status, nil
}

func (d *DeepCodeLLMBindingImpl) autofixRequestBody(options *AutofixOptions) ([]byte, error) {
	request := AutofixRequest{
		Key: AutofixRequestKey{
			Type:     "file",
			Hash:     options.BundleHash,
			FilePath: options.FilePath,
			RuleId:   options.RuleID,
			LineNum:  options.LineNum,
		},
		AnalysisContext:     options.CodeRequestContext,
		IdeExtensionDetails: options.IdeExtensionDetails,
	}
	if len(options.ShardKey) > 0 {
		request.Key.Shard = options.ShardKey
	}

	requestBody, err := json.Marshal(request)
	return requestBody, err
}

func (d *DeepCodeLLMBindingImpl) submitAutofixFeedback(ctx context.Context, options AutofixFeedbackOptions) error {
	span := d.instrumentor.StartSpan(ctx, "code.SubmitAutofixFeedback")
	defer span.Finish()

	logger := d.logger.With().Str("method", "code.SubmitAutofixFeedback").Str("requestId", span.GetTraceId()).Logger()

	endpoint, err := url.Parse(fmt.Sprintf("%s/autofix/event", options.Host))
	if err != nil {
		logger.Err(err).Str("host", options.Host).Msg("error creating endpoint URL")
		return err
	}

	requestBody, err := d.autofixFeedbackRequestBody(&options)
	if err != nil {
		logger.Err(err).Str("requestBody", string(requestBody)).Msg("error creating request body")
		return err
	}

	logger.Info().Msg("Started obtaining autofix Response")
	_, err = d.submitRequest(span.Context(), endpoint, requestBody, options.CodeRequestContext.Org.PublicId)
	logger.Info().Msg("Finished obtaining autofix Response")

	return err
}

func (d *DeepCodeLLMBindingImpl) autofixFeedbackRequestBody(options *AutofixFeedbackOptions) ([]byte, error) {
	request := AutofixUserEvent{
		Channel:             "IDE",
		EventType:           options.Result,
		EventDetails:        AutofixEventDetails{FixId: options.FixID},
		AnalysisContext:     options.CodeRequestContext,
		IdeExtensionDetails: options.IdeExtensionDetails,
	}

	requestBody, err := json.Marshal(request)

	return requestBody, err
}

func prepareDiffs(diffs []string) []string {
	cleanedDiffs := make([]string, 0, len(diffs))
	for _, diff := range diffs {
		diffLines := strings.Split(diff, "\n")
		cleanedLines := ""
		for _, line := range diffLines {
			if !strings.HasPrefix(line, "---") && !strings.HasPrefix(line, "+++") {
				cleanedLines += line + "\n"
			}
		}
		cleanedDiffs = append(cleanedDiffs, cleanedLines)
	}
	var encodedDiffs []string
	for _, diff := range cleanedDiffs {
		encodedDiffs = append(encodedDiffs, base64.StdEncoding.EncodeToString([]byte(diff)))
	}
	return encodedDiffs
}
