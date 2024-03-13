/*
 * © 2022-2024 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package http

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"

	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/snyk-ls/application/config"
	"github.com/snyk/snyk-ls/infrastructure/code/encoding"
)

//go:generate mockgen -destination=mocks/http.go -source=http.go -package mocks
type HTTPClient interface {
	DoCall(ctx context.Context,
		method string,
		path string,
		requestBody []byte,
	) (responseBody []byte, err error)
}

type httpClient struct {
	client        func() *http.Client
	instrumentor  observability.Instrumentor
	errorReporter observability.ErrorReporter
}

func NewHTTPClient(
	client func() *http.Client,
	instrumentor observability.Instrumentor,
	errorReporter observability.ErrorReporter,
) HTTPClient {
	return &httpClient{client, instrumentor, errorReporter}
}

var retryErrorCodes = map[int]bool{
	http.StatusServiceUnavailable:  true,
	http.StatusBadGateway:          true,
	http.StatusGatewayTimeout:      true,
	http.StatusInternalServerError: true,
}

func (s *httpClient) DoCall(ctx context.Context,
	method string,
	path string,
	requestBody []byte,
) (responseBody []byte, err error) {
	span := s.instrumentor.StartSpan(ctx, "code.DoCall")
	defer s.instrumentor.Finish(span)

	const retryCount = 3
	for i := 0; i < retryCount; i++ {
		requestId := span.GetTraceId()

		var bodyBuffer *bytes.Buffer
		bodyBuffer, err = s.encodeIfNeeded(method, requestBody)
		if err != nil {
			return nil, err
		}

		c := config.CurrentConfig()

		var req *http.Request
		req, err = s.newRequest(c, method, path, bodyBuffer, requestId)
		if err != nil {
			return nil, err
		}

		log.Trace().Str("requestBody", string(requestBody)).Str("snyk-request-id", requestId).Msg("SEND TO REMOTE")

		var response *http.Response
		response, responseBody, err = s.httpCall(req) //nolint:bodyclose // Already closed before in httpCall

		if response != nil && responseBody != nil {
			log.Trace().Str("response.Status", response.Status).Str("responseBody", string(responseBody)).Str("snyk-request-id", requestId).Msg("RECEIVED FROM REMOTE")
		} else {
			log.Trace().Str("snyk-request-id", requestId).Msg("RECEIVED FROM REMOTE")
		}

		if err != nil {
			return nil, err // no retries for errors
		}

		err = s.checkResponseCode(response)
		if err != nil {
			if retryErrorCodes[response.StatusCode] {
				log.Debug().Err(err).Str("method", method).Int("attempts done", i+1).Msg("retrying")
				if i < retryCount-1 {
					time.Sleep(5 * time.Second)
					continue
				}
				// return the error on last try
				return nil, err
			}
			return nil, err
		}
		// no error, we can break the retry loop
		break
	}
	return responseBody, err
}

func (s *httpClient) newRequest(
	c *config.Config,
	method string,
	path string,
	body *bytes.Buffer,
	requestId string,
) (*http.Request, error) {
	host, err := GetCodeApiURL(c)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(method, host+path, body)
	if err != nil {
		return nil, err
	}

	s.addOrganization(c, req)
	s.addDefaultHeaders(req, requestId, method)
	return req, nil
}

func (s *httpClient) httpCall(req *http.Request) (*http.Response, []byte, error) {
	method := "code.httpCall"
	response, err := s.client().Do(req)
	if err != nil {
		log.Error().Err(err).Str("method", method).Msg("got http error")
		s.errorReporter.CaptureErrorAndReportAsIssue(req.RequestURI, err)
		return nil, nil, err
	}

	defer func(Body io.ReadCloser) {
		closeErr := Body.Close()
		if closeErr != nil {
			log.Error().Err(closeErr).Msg("Couldn't close response body in call to Snyk Code")
		}
	}(response.Body)
	responseBody, err := io.ReadAll(response.Body)

	if err != nil {
		log.Error().Err(err).Str("method", method).Msg("error reading response body")
		s.errorReporter.CaptureErrorAndReportAsIssue(req.RequestURI, err)
		return nil, nil, err
	}
	return response, responseBody, nil
}

func (s *httpClient) addOrganization(c *config.Config, req *http.Request) {
	// Setting a chosen org name for the request
	org := c.Organization()
	if org != "" {
		req.Header.Set("snyk-org-name", org)
	}
}

func (s *httpClient) addDefaultHeaders(req *http.Request, requestId string, method string) {
	req.Header.Set("snyk-request-id", requestId)
	// https://www.keycdn.com/blog/http-cache-headers
	req.Header.Set("Cache-Control", "private, max-age=0, no-cache")
	if s.mustBeEncoded(method) {
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Encoding", "gzip")
	} else {
		req.Header.Set("Content-Type", "application/json")
	}
}

func (s *httpClient) encodeIfNeeded(method string, requestBody []byte) (*bytes.Buffer, error) {
	b := new(bytes.Buffer)
	mustBeEncoded := s.mustBeEncoded(method)
	if mustBeEncoded {
		enc := encoding.NewEncoder(b)
		_, err := enc.Write(requestBody)
		if err != nil {
			return nil, err
		}
	} else {
		b = bytes.NewBuffer(requestBody)
	}
	return b, nil
}

func (s *httpClient) mustBeEncoded(method string) bool {
	return method == http.MethodPost || method == http.MethodPut
}

func (s *httpClient) checkResponseCode(r *http.Response) error {
	if r.StatusCode >= 200 && r.StatusCode <= 299 {
		return nil
	}
	return errors.New("Unexpected response code: " + r.Status)
}
