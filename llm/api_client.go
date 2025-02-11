package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/url"

	"github.com/snyk/code-client-go/observability"
)

const (
	completeStatus                = "COMPLETE"
	failedToObtainRequestIdString = "Failed to obtain request id. "
	defaultEndpointURL            = "http://localhost:10000/explain"
)

func (d *DeepcodeLLMBinding) runExplain(ctx context.Context, options ExplainOptions) (explainResponse, error) {
	requestId, err := observability.GetTraceId(ctx)
	span := d.instrumentor.StartSpan(ctx, "code.RunExplain")
	defer span.Finish()
	logger := d.logger.With().Str("method", "code.RunExplain").Str("requestId", requestId).Logger()

	if err != nil {
		logger.Err(err).Msg(failedToObtainRequestIdString + err.Error())
		return explainResponse{}, err
	}

	logger.Debug().Msg("API: Retrieving explain for bundle")
	defer logger.Debug().Msg("API: Retrieving explain done")

	// construct the requestBody depending on the values given from IDE.
	requestBody, err := d.explainRequestBody(&options)
	if err != nil {
		logger.Err(err).Str("requestBody", string(requestBody)).Msg("error creating request body")
		return explainResponse{}, err
	}

	u := d.endpoint
	if u == nil {
		u, err = url.Parse(defaultEndpointURL)
		if err != nil {
			logger.Err(err).Send()
			return explainResponse{}, err
		}
	}
	logger.Debug().Str("payload body: %s\n", string(requestBody)).Msg("Marshaled payload")
	resp, err := d.httpClientFunc().Post(u.String(), "application/json", bytes.NewBuffer(requestBody))
	if err != nil {
		logger.Err(err).Str("requestBody", string(requestBody)).Msg("error getting response")
		return explainResponse{}, err
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
		return explainResponse{}, err
	}
	logger.Debug().Str("response body: %s\n", string(responseBody)).Msg("Got the response")

	if err != nil {
		return explainResponse{}, err
	}

	var response explainResponse
	response.Status = completeStatus
	err = json.Unmarshal(responseBody, &response)
	if err != nil {
		logger.Err(err).Str("responseBody", string(responseBody)).Msg("error unmarshalling")
		return explainResponse{}, err
	}
	return response, nil
}

func (d *DeepcodeLLMBinding) explainRequestBody(options *ExplainOptions) ([]byte, error) {
	logger := d.logger.With().Str("method", "code.explainRequestBody").Logger()

	var request explainRequest
	if options.diff == "" {
		request.VulnExplanation = &explainVulnerabilityRequest{
			RuleId:            options.RuleKey,
			Derivation:        options.Derivation,
			RuleMessage:       options.ruleMessage,
			ExplanationLength: SHORT,
		}
		logger.Debug().Msg("payload for VulnExplanation")
	} else {
		request.FixExplanation = &explainFixRequest{
			RuleId:            options.RuleKey,
			Diff:              options.diff,
			ExplanationLength: SHORT,
		}
		logger.Debug().Msg("payload for FixExplanation")
	}
	requestBody, err := json.Marshal(request)
	return requestBody, err
}
