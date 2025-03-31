/*
 * © 2024 Snyk Limited All rights reserved.
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
package http_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	codeClientHTTP "github.com/snyk/code-client-go/v2/http"
	"github.com/snyk/code-client-go/v2/observability/mocks"
)

// dummyTransport is a transport struct that always returns the response code specified in the constructor
type dummyTransport struct {
	responseCode int
	status       string
	calls        int
}

func (d *dummyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	d.calls++
	if req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		if string(body) == "" {
			return nil, fmt.Errorf("body is empty")
		}
	}
	return &http.Response{
		StatusCode: d.responseCode,
		Status:     d.status,
	}, nil
}

func TestSnykCodeBackendService_DoCall_shouldRetryWithARequestBody(t *testing.T) {
	d := &dummyTransport{responseCode: 502, status: "502 Bad Gateway"}
	dummyClientFactory := func() *http.Client {
		return &http.Client{
			Transport: d,
		}
	}

	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).Times(1)
	mockInstrumentor.EXPECT().Finish(gomock.Any()).Times(1)
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1", io.NopCloser(strings.NewReader("body")))
	require.NoError(t, err)

	s := codeClientHTTP.NewHTTPClient(
		dummyClientFactory,
		codeClientHTTP.WithRetryCount(3),
		codeClientHTTP.WithInstrumentor(mockInstrumentor),
		codeClientHTTP.WithErrorReporter(mockErrorReporter),
		codeClientHTTP.WithLogger(newLogger(t)),
	)
	res, err := s.Do(req)
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, 4, d.calls)
}

func TestSnykCodeBackendService_DoCall_shouldSucceed(t *testing.T) {
	d := &dummyTransport{responseCode: 200}
	dummyClientFactory := func() *http.Client {
		return &http.Client{
			Transport: d,
		}
	}

	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).Times(1)
	mockInstrumentor.EXPECT().Finish(gomock.Any()).Times(1)
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

	req, err := http.NewRequest(http.MethodGet, "https://httpstat.us/200", nil)
	require.NoError(t, err)

	s := codeClientHTTP.NewHTTPClient(
		dummyClientFactory,
		codeClientHTTP.WithRetryCount(3),
		codeClientHTTP.WithInstrumentor(mockInstrumentor),
		codeClientHTTP.WithErrorReporter(mockErrorReporter),
		codeClientHTTP.WithLogger(newLogger(t)),
	)
	res, err := s.Do(req)
	assert.NoError(t, err)
	assert.NotNil(t, res)
	assert.Equal(t, 1, d.calls)
}

func TestSnykCodeBackendService_DoCall_shouldFail(t *testing.T) {
	d := &dummyTransport{responseCode: 400, status: "400 Bad Request"}
	dummyClientFactory := func() *http.Client {
		return &http.Client{
			Transport: d,
		}
	}

	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).Times(1)
	mockInstrumentor.EXPECT().Finish(gomock.Any()).Times(1)
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

	req, err := http.NewRequest(http.MethodGet, "https://127.0.0.1", nil)
	require.NoError(t, err)

	s := codeClientHTTP.NewHTTPClient(
		dummyClientFactory,
		codeClientHTTP.WithRetryCount(1),
		codeClientHTTP.WithInstrumentor(mockInstrumentor),
		codeClientHTTP.WithErrorReporter(mockErrorReporter),
		codeClientHTTP.WithLogger(newLogger(t)),
	)
	response, err := s.Do(req)
	assert.Equal(t, "400 Bad Request", response.Status)
	assert.NoError(t, err)
}

func newLogger(t *testing.T) *zerolog.Logger {
	t.Helper()
	logger := zerolog.New(zerolog.NewTestWriter(t))
	return &logger
}
