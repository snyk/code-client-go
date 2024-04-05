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

// Package http defines the HTTP client used to interact with the Snyk Code API.
package http

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/code-client-go/observability"
)

//go:generate mockgen -destination=mocks/http.go -source=http.go -package mocks
type HTTPClient interface {
	DoCall(ctx context.Context,
		host string,
		headers map[string]string,
		method string,
		path string,
		requestBody *bytes.Buffer,
	) (responseBody []byte, err error)
}

type httpClient struct {
	clientFactory func() *http.Client
	instrumentor  observability.Instrumentor
	errorReporter observability.ErrorReporter
	logger        *zerolog.Logger
}

func NewHTTPClient(
	logger *zerolog.Logger,
	clientFactory func() *http.Client,
	instrumentor observability.Instrumentor,
	errorReporter observability.ErrorReporter,
) HTTPClient {
	return &httpClient{clientFactory, instrumentor, errorReporter, logger}
}

var retryErrorCodes = map[int]bool{
	http.StatusServiceUnavailable:  true,
	http.StatusBadGateway:          true,
	http.StatusGatewayTimeout:      true,
	http.StatusInternalServerError: true,
}

// TODO: conver to doer (request outside of docall and rename docall to do)
func (s *httpClient) DoCall(ctx context.Context,
	host string,
	headers map[string]string,
	method string,
	path string,
	requestBody *bytes.Buffer,
) (responseBody []byte, err error) {
	span := s.instrumentor.StartSpan(ctx, "http.DoCall")
	defer s.instrumentor.Finish(span)

	const retryCount = 3
	for i := 0; i < retryCount; i++ {
		requestId := span.GetTraceId()
		headers["snyk-request-id"] = requestId

		var req *http.Request
		req, err = s.newRequest(host, headers, method, path, requestBody)
		if err != nil {
			return nil, err
		}

		s.logger.Trace().Str("requestBody", requestBody.String()).Str("snyk-request-id", requestId).Msg("SEND TO REMOTE")

		var response *http.Response
		response, responseBody, err = s.httpCall(req) //nolint:bodyclose // Already closed before in httpCall

		if response != nil && responseBody != nil {
			s.logger.Trace().Str("response.Status", response.Status).Str("responseBody", string(responseBody)).Str("snyk-request-id", requestId).Msg("RECEIVED FROM REMOTE")
		} else {
			s.logger.Trace().Str("snyk-request-id", requestId).Msg("RECEIVED FROM REMOTE")
		}

		if err != nil {
			return nil, err // no retries for errors
		}

		err = s.checkResponseCode(response)
		if err != nil {
			if retryErrorCodes[response.StatusCode] {
				s.logger.Debug().Err(err).Str("method", method).Int("attempts done", i+1).Msg("retrying")
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
	host string,
	headers map[string]string,
	method string,
	path string,
	body *bytes.Buffer,
) (*http.Request, error) {
	if body == nil {
		body = bytes.NewBufferString("")
	}
	req, err := http.NewRequest(method, host+path, body)
	if err != nil {
		return nil, err
	}

	s.addHeaders(req, headers)
	return req, nil
}

func (s *httpClient) httpCall(req *http.Request) (*http.Response, []byte, error) {
	log := s.logger.With().Str("method", "code.httpCall").Logger()
	response, err := s.clientFactory().Do(req)
	if err != nil {
		log.Error().Err(err).Msg("got http error")
		s.errorReporter.CaptureError(err, observability.ErrorReporterOptions{ErrorDiagnosticPath: req.RequestURI})
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
		log.Error().Err(err).Msg("error reading response body")
		s.errorReporter.CaptureError(err, observability.ErrorReporterOptions{ErrorDiagnosticPath: req.RequestURI})
		return nil, nil, err
	}
	return response, responseBody, nil
}

func (s *httpClient) addHeaders(req *http.Request, headers map[string]string) {
	for key, value := range headers {
		req.Header.Set(key, value)
	}
}

func (s *httpClient) checkResponseCode(r *http.Response) error {
	if r.StatusCode >= 200 && r.StatusCode <= 299 {
		return nil
	}
	return errors.New("Unexpected response code: " + r.Status)
}
