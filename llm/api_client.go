package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"

	"github.com/snyk/code-client-go/observability"
)

const (
	completeStatus                = "COMPLETE"
	failedToObtainRequestIdString = "Failed to obtain request id. "
	defaultEndpointURL            = "http://localhost:10000/explain"
)

func (d *DeepcodeLLMBinding) runExplain(ctx context.Context, options ExplainOptions) (explainResponse, error) {
	span := d.instrumentor.StartSpan(ctx, "code.RunExplain")
	defer span.Finish()

	requestId, err := observability.GetTraceId(ctx)
	logger := d.logger.With().Str("method", "code.RunExplain").Str("requestId", requestId).Logger()
	if err != nil {
		logger.Err(err).Msg(failedToObtainRequestIdString + err.Error())
		return explainResponse{}, err
	}

	logger.Debug().Msg("API: Retrieving explain for bundle")
	defer logger.Debug().Msg("API: Retrieving explain done")

	requestBody, err := d.explainRequestBody(&options)
	if err != nil {
		logger.Err(err).Str("requestBody", string(requestBody)).Msg("error creating request body")
		return explainResponse{}, err
	}
	logger.Debug().Str("payload body: %s\n", string(requestBody)).Msg("Marshaled payload")

	u := d.endpoint
	if u == nil {
		u, err = url.Parse(defaultEndpointURL)
		if err != nil {
			logger.Err(err).Send()
			return explainResponse{}, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), bytes.NewBuffer(requestBody))
	if err != nil {
		logger.Err(err).Str("requestBody", string(requestBody)).Msg("error creating request")
		return explainResponse{}, err
	}

	d.addDefaultHeaders(req, requestId)

	resp, err := d.httpClientFunc().Do(req)
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
	if options.Diff == "" {
		request.VulnExplanation = &explainVulnerabilityRequest{
			RuleId:            options.RuleKey,
			Derivation:        options.Derivation,
			RuleMessage:       options.RuleMessage,
			ExplanationLength: SHORT,
		}
		logger.Debug().Msg("payload for VulnExplanation")
	} else {
		request.FixExplanation = &explainFixRequest{
			RuleId:            options.RuleKey,
			Diff:              options.Diff,
			ExplanationLength: SHORT,
		}
		logger.Debug().Msg("payload for FixExplanation")
	}
	requestBody, err := json.Marshal(request)
	return requestBody, err
}

func (d *DeepcodeLLMBinding) addDefaultHeaders(req *http.Request, requestId string) {
	req.Header.Set("snyk-request-id", requestId)
	req.Header.Set("Cache-Control", "private, max-age=0, no-cache")
	req.Header.Set("Content-Type", "application/json")
}
