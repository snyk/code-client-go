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

//go:generate go tool github.com/golang/mock/mockgen -destination=mocks/http.go -source=http.go -package mocks

type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type HTTPClientFactory func() *http.Client

type httpClient struct {
	retryCount        int
	httpClientFactory HTTPClientFactory
	instrumentor      observability.Instrumentor
	errorReporter     observability.ErrorReporter
	logger            *zerolog.Logger
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
		h.errorReporter = observability.NewErrorReporter(logger)
	}
}

func NewHTTPClient(
	httpClientFactory HTTPClientFactory,
	options ...OptionFunc,
) HTTPClient {
	nopLogger := zerolog.Nop()
	instrumentor := observability.NewInstrumentor()
	errorReporter := observability.NewErrorReporter(&nopLogger)
	client := &httpClient{
		retryCount:        3,
		httpClientFactory: httpClientFactory,
		instrumentor:      instrumentor,
		errorReporter:     errorReporter,
		logger:            &nopLogger,
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

func (s *httpClient) Do(req *http.Request) (*http.Response, error) {
	span := s.instrumentor.StartSpan(req.Context(), "http.Do")
	defer s.instrumentor.Finish(span)

	retryCount := s.retryCount
	for {
		requestId := span.GetTraceId()
		req.Header.Set("snyk-request-id", requestId)

		response, err := s.httpCall(req)
		if err != nil {
			return nil, err // no retries for errors
		}

		if retryCount > 0 && retryErrorCodes[response.StatusCode] {
			s.logger.Debug().Err(err).Int("attempts left", retryCount).Msg("retrying")
			retryCount--
			time.Sleep(5 * time.Second)
			continue
		}

		// should return
		return response, err
	}
}

func (s *httpClient) httpCall(req *http.Request) (*http.Response, error) {
	// store the request body so that after retrying it can be read again
	var copyReqBody io.ReadCloser
	var reqBuf []byte
	if req.Body != nil {
		reqBuf, _ = io.ReadAll(req.Body)
		reqBody := io.NopCloser(bytes.NewBuffer(reqBuf))
		copyReqBody = io.NopCloser(bytes.NewBuffer(reqBuf))
		req.Body = reqBody
	}

	response, err := s.httpClientFactory().Do(req)
	req.Body = copyReqBody
	if response != nil {
		var copyResBody io.ReadCloser
		var resBuf []byte
		resBuf, _ = io.ReadAll(response.Body)
		copyResBody = io.NopCloser(bytes.NewBuffer(resBuf))
		response.Body = copyResBody
	}

	if err != nil {
		s.errorReporter.CaptureError(err, observability.ErrorReporterOptions{ErrorDiagnosticPath: req.RequestURI})
		return nil, err
	}

	return response, nil
}

func NewDefaultClientFactory() HTTPClientFactory {
	clientFunc := func() *http.Client { return http.DefaultClient }
	return clientFunc
}

func AddDefaultHeaders(req *http.Request, requestId string, orgId string) {
	// if requestId is empty it will be enriched from the Gateway
	if len(requestId) > 0 {
		req.Header.Set("snyk-request-id", requestId)
	}
	if len(orgId) > 0 {
		req.Header.Set("snyk-org-name", orgId)
	}
	req.Header.Set("Cache-Control", "private, max-age=0, no-cache")
	req.Header.Set("Content-Type", "application/json")
}
