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
	"io"
	"net/http"
	"time"

	"github.com/rs/zerolog"

	"github.com/snyk/code-client-go/observability"
)

//go:generate mockgen -destination=mocks/http.go -source=http.go -package mocks
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type httpClient struct {
	retryCount    int
	clientFactory func() *http.Client
	instrumentor  observability.Instrumentor
	errorReporter observability.ErrorReporter
	logger        *zerolog.Logger
}

type OptionFunc func(*httpClient)

func WithRetryCount(retryCount int) OptionFunc {
	return func(h *httpClient) {
		h.retryCount = retryCount
	}
}

func WithInstrumentor(instrumentor observability.Instrumentor) OptionFunc {
	return func(h *httpClient) {
		h.instrumentor = instrumentor
	}
}

func WithErrorReporter(errorReporter observability.ErrorReporter) OptionFunc {
	return func(h *httpClient) {
		h.errorReporter = errorReporter
	}
}

func WithLogger(logger *zerolog.Logger) OptionFunc {
	return func(h *httpClient) {
		h.logger = logger
	}
}

func NewHTTPClient(
	clientFactory func() *http.Client,
	options ...OptionFunc,
) HTTPClient {
	nopLogger := zerolog.Nop()
	instrumentor := observability.NewInstrumentor()
	errorReporter := observability.NewErrorReporter(&nopLogger)
	client := &httpClient{
		retryCount:    3,
		clientFactory: clientFactory,
		instrumentor:  instrumentor,
		errorReporter: errorReporter,
		logger:        &nopLogger,
	}

	for _, option := range options {
		option(client)
	}

	return client
}

var retryErrorCodes = map[int]bool{
	http.StatusServiceUnavailable:  true,
	http.StatusBadGateway:          true,
	http.StatusGatewayTimeout:      true,
	http.StatusInternalServerError: true,
}

func (s *httpClient) Do(req *http.Request) (response *http.Response, err error) {
	span := s.instrumentor.StartSpan(req.Context(), "http.Do")
	defer s.instrumentor.Finish(span)

	for i := 0; i < s.retryCount; i++ {
		requestId := span.GetTraceId()
		req.Header.Set("snyk-request-id", requestId)

		response, err = s.httpCall(req)
		if err != nil {
			return nil, err // no retries for errors
		}

		if retryErrorCodes[response.StatusCode] {
			s.logger.Debug().Err(err).Str("method", req.Method).Int("attempts done", i+1).Msg("retrying")
			if i < s.retryCount-1 {
				time.Sleep(5 * time.Second)
				continue
			}
		}

		// no error, we can break the retry loop
		break
	}
	return response, err
}

func (s *httpClient) httpCall(req *http.Request) (*http.Response, error) {
	log := s.logger.With().Str("method", "http.httpCall").Logger()
	requestId := req.Header.Get("snyk-request-id")

	// store the request body so that after retrying it can be read again
	var copyReqBody io.ReadCloser
	var reqBuf []byte
	if req.Body != nil {
		reqBuf, _ = io.ReadAll(req.Body)
		reqBody := io.NopCloser(bytes.NewBuffer(reqBuf))
		copyReqBody = io.NopCloser(bytes.NewBuffer(reqBuf))
		req.Body = reqBody
		s.logger.Debug().Str("url", req.URL.String()).Str("snyk-request-id", requestId).Str("requestBody", string(reqBuf)).Msg("SEND TO REMOTE")
	}
	response, err := s.clientFactory().Do(req)
	req.Body = copyReqBody
	if response != nil {
		var copyResBody io.ReadCloser
		var resBuf []byte
		resBuf, _ = io.ReadAll(response.Body)
		copyResBody = io.NopCloser(bytes.NewBuffer(resBuf))
		response.Body = copyResBody
		s.logger.Debug().Str("url", req.URL.String()).Str("response.Status", response.Status).Str("snyk-request-id", requestId).Str("responseBody", string(resBuf)).Msg("RECEIVED FROM REMOTE")
	} else {
		s.logger.Debug().Str("url", req.URL.String()).Str("snyk-request-id", requestId).Msg("RECEIVED FROM REMOTE")
	}

	if err != nil {
		log.Error().Err(err).Msg("got http error")
		s.errorReporter.CaptureError(err, observability.ErrorReporterOptions{ErrorDiagnosticPath: req.RequestURI})
		return nil, err
	}

	return response, nil
}
