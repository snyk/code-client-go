package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/snyk/code-client-go/observability"
	"io"
	"net/http"
	"net/url"
)

const (
	completeStatus                = "COMPLETE"
	failedToObtainRequestIdString = "Failed to obtain request id. "
	defaultEndpointURL            = "http://localhost:10000/explain"
)

var HardCodedResponse = "{\n    \"explanation\": \n        {\n            \"explanation1\": \"This is the first explanation\",\n            \"explanation2\": \"this is the second explanation\",\n            \"explanation3\": \"This is the third explanation\",\n            \"explanation4\": \"This is the fourth explanation\",\n            \"explanation5\": \"This is the fifth explanation\"\n        }\n}"

func (d *DeepCodeLLMBindingImpl) runExplain(ctx context.Context, options ExplainOptions) (Explanations, error) {
	span := d.instrumentor.StartSpan(ctx, "code.RunExplain")
	defer span.Finish()

	requestId, err := observability.GetTraceId(ctx)
	logger := d.logger.With().Str("method", "code.RunExplain").Str("requestId", requestId).Logger()
	if err != nil {
		logger.Err(err).Msg(failedToObtainRequestIdString + err.Error())
		return Explanations{}, err
	}

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

	d.addDefaultHeaders(req, requestId)

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
	responseBody = []byte(HardCodedResponse)
	//if err != nil {
	//	logger.Err(err).Str("requestBody", string(requestBody)).Msg("error reading all response")
	//	return Explanations{}, err
	//}
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

	var request explainRequest
	if len(options.Diffs) == 0 {
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
			Diffs:             options.Diffs,
			ExplanationLength: SHORT,
		}
		logger.Debug().Msg("payload for FixExplanation")
	}
	requestBody, err := json.Marshal(request)
	return requestBody, err
}

func (d *DeepCodeLLMBindingImpl) addDefaultHeaders(req *http.Request, requestId string) {
	req.Header.Set("snyk-request-id", requestId)
	req.Header.Set("Cache-Control", "private, max-age=0, no-cache")
	req.Header.Set("Content-Type", "application/json")
}
