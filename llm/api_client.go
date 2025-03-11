package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
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

	u := d.endpoint
	if u == nil {
		u, err = url.Parse(defaultEndpointURL)
		if err != nil {
			logger.Err(err).Send()
			return Explanations{}, err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewBuffer(requestBody))
	if err != nil {
		logger.Err(err).Str("requestBody", string(requestBody)).Msg("error creating request")
		return Explanations{}, err
	}

	d.addDefaultHeaders(req)

	resp, err := d.httpClientFunc().Do(req) //nolint:bodyclose // this seems to be a false positive
	if err != nil {
		logger.Err(err).Str("requestBody", string(requestBody)).Msg("error getting response")
		return Explanations{}, err
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
		return Explanations{}, err
	}
	logger.Debug().Str("response body: %s\n", string(responseBody)).Msg("Got the response")
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
			Diffs:             options.Diffs,
			ExplanationLength: SHORT,
		})
		logger.Debug().Msg("payload for FixExplanation")
	}
	return requestBody, marshalErr
}

func (d *DeepCodeLLMBindingImpl) addDefaultHeaders(req *http.Request) {
	req.Header.Set("Cache-Control", "private, max-age=0, no-cache")
	req.Header.Set("Content-Type", "application/json")
}
