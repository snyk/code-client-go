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
	"context"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/stretchr/testify/assert"

	codeClientHTTP "github.com/snyk/code-client-go/internal/http"
	"github.com/snyk/code-client-go/internal/util/testutil"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/observability/mocks"
)

// dummyTransport is a transport struct that always returns the response code specified in the constructor
type dummyTransport struct {
	responseCode int
	status       string
	calls        int
}

func (d *dummyTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	d.calls++
	return &http.Response{
		StatusCode: d.responseCode,
		Status:     d.status,
	}, nil
}

func TestSnykCodeBackendService_DoCall_shouldRetry(t *testing.T) {
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

	s := codeClientHTTP.NewHTTPClient(workflow.NewDefaultWorkFlowEngine(), dummyClientFactory, mockInstrumentor, testutil.NewTestErrorReporter(), observability.ErrorReporterOptions{})
	_, err := s.DoCall(context.Background(), configuration.New(), "", "GET", "https: //httpstat.us/500", nil)
	assert.Error(t, err)
	assert.Equal(t, 3, d.calls)
}

func TestSnykCodeBackendService_doCall_rejected(t *testing.T) {
	dummyClientFactory := func() *http.Client {
		return &http.Client{}
	}

	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).Times(1)
	mockInstrumentor.EXPECT().Finish(gomock.Any()).Times(1)

	s := codeClientHTTP.NewHTTPClient(workflow.NewDefaultWorkFlowEngine(), dummyClientFactory, mockInstrumentor, testutil.NewTestErrorReporter(), observability.ErrorReporterOptions{})
	_, err := s.DoCall(context.Background(), configuration.New(), "", "GET", "https://127.0.0.1", nil)
	assert.Error(t, err)
}
