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
package analysis_test

import (
	"bytes"
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	confMocks "github.com/snyk/code-client-go/config/mocks"
	httpmocks "github.com/snyk/code-client-go/http/mocks"
	"github.com/snyk/code-client-go/internal/analysis"
	"github.com/snyk/code-client-go/observability/mocks"
	"github.com/snyk/code-client-go/scan"
)

func setup(t *testing.T) (*confMocks.MockConfig, *httpmocks.MockHTTPClient, *mocks.MockInstrumentor, *mocks.MockErrorReporter, zerolog.Logger) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockSpan.EXPECT().Context().AnyTimes()
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().Organization().AnyTimes().Return("")
	mockConfig.EXPECT().SnykApi().AnyTimes().Return("http://localhost")

	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)

	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
	mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

	logger := zerolog.Nop()
	return mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, logger
}

func TestAnalysis_CreateWorkspace(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, logger := setup(t)

	mockHTTPClient.EXPECT().Do(
		mock.MatchedBy(func(i interface{}) bool {
			req := i.(*http.Request)
			return req.URL.String() == "http://localhost/hidden/orgs/4a72d1db-b465-4764-99e1-ecedad03b06a/workspaces?version=2024-03-12~experimental" &&
				req.Method == "POST" &&
				req.Header.Get("Content-Type") == "application/vnd.api+json" &&
				req.Header.Get("Snyk-Request-Id") == "b372d1db-b465-4764-99e1-ecedad03b06a" &&
				req.Header.Get("User-Agent") == "cli"
		}),
	).Return(&http.Response{
		StatusCode: http.StatusCreated,
		Header: http.Header{
			"Content-Type": []string{"application/vnd.api+json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"data":{"id": "c172d1db-b465-4764-99e1-ecedad03b06a"}}`))),
	}, nil).Times(1)

	target, err := scan.NewRepositoryTargetFromPath("../../")
	assert.NoError(t, err)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
	_, err = analysisOrchestrator.CreateWorkspace(
		context.Background(),
		"4a72d1db-b465-4764-99e1-ecedad03b06a",
		"b372d1db-b465-4764-99e1-ecedad03b06a",
		target,
		"testBundleHash")
	assert.NoError(t, err)
}

func TestAnalysis_CreateWorkspace_NotARepository(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, logger := setup(t)
	mockErrorReporter.EXPECT().CaptureError(gomock.Any(), gomock.Any())

	repoDir := t.TempDir()
	target, err := scan.NewRepositoryTargetFromPath(repoDir)
	assert.ErrorContains(t, err, "open local repository")

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
	_, err = analysisOrchestrator.CreateWorkspace(
		context.Background(),
		"4a72d1db-b465-4764-99e1-ecedad03b06a",
		"b372d1db-b465-4764-99e1-ecedad03b06a",
		target,
		"testBundleHash",
	)
	assert.ErrorContains(t, err, "workspace is not a repository")
}

func TestAnalysis_CreateWorkspace_Failure(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, logger := setup(t)

	mockHTTPClient.EXPECT().Do(
		mock.MatchedBy(func(i interface{}) bool {
			req := i.(*http.Request)
			return req.URL.String() == "http://localhost/hidden/orgs/4a72d1db-b465-4764-99e1-ecedad03b06a/workspaces?version=2024-03-12~experimental" &&
				req.Method == "POST" &&
				req.Header.Get("Content-Type") == "application/vnd.api+json" &&
				req.Header.Get("Snyk-Request-Id") == "b372d1db-b465-4764-99e1-ecedad03b06a" &&
				req.Header.Get("User-Agent") == "cli"
		}),
	).Return(&http.Response{
		StatusCode: http.StatusBadRequest,
		Header: http.Header{
			"Content-Type": []string{"application/vnd.api+json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"errors": [{"detail": "error detail", "status": "400"}], "jsonapi": {"version": "version"}}`))),
	}, nil).Times(1)

	target, err := scan.NewRepositoryTargetFromPath("../../")
	assert.NoError(t, err)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
	_, err = analysisOrchestrator.CreateWorkspace(
		context.Background(),
		"4a72d1db-b465-4764-99e1-ecedad03b06a",
		"b372d1db-b465-4764-99e1-ecedad03b06a",
		target,
		"testBundleHash")
	assert.ErrorContains(t, err, "error detail")
}

func TestAnalysis_CreateWorkspace_KnownErrors(t *testing.T) {
	type testCase struct {
		name           string
		expectedStatus int
		expectedError  string
	}

	testCases := []testCase{
		{
			name:           "StatusBadRequest",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "400",
		},
		{
			name:           "StatusUnauthorized",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "401",
		},
		{
			name:           "StatusForbidden",
			expectedStatus: http.StatusForbidden,
			expectedError:  "403",
		},
		{
			name:           "StatusInternalServerError",
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "500",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockSpan := mocks.NewMockSpan(ctrl)
			mockSpan.EXPECT().GetTraceId().AnyTimes()
			mockSpan.EXPECT().Context().AnyTimes()
			mockConfig := confMocks.NewMockConfig(ctrl)
			mockConfig.EXPECT().Organization().AnyTimes().Return("")
			mockConfig.EXPECT().SnykApi().AnyTimes().Return("http://localhost")

			mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)
			mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
				req := i.(*http.Request)
				return req.URL.String() == "http://localhost/hidden/orgs/4a72d1db-b465-4764-99e1-ecedad03b06a/workspaces?version=2024-03-12~experimental" &&
					req.Method == "POST"
			})).Times(1).Return(&http.Response{
				StatusCode: tc.expectedStatus,
				Header: http.Header{
					"Content-Type": []string{"application/vnd.api+json"},
				},
				Body: io.NopCloser(bytes.NewReader([]byte(fmt.Sprintf(`{"jsonapi":{"version":"1.0"},"errors":[{"id":"05ebb47a-631a-485a-8db6-5ed0b3943eb0","detail":"%s"}]}`, tc.expectedError)))),
			}, nil)

			mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
			mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
			mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
			mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

			logger := zerolog.Nop()

			target, err := scan.NewRepositoryTargetFromPath("../../")
			assert.NoError(t, err)

			analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
			_, err = analysisOrchestrator.CreateWorkspace(
				context.Background(),
				"4a72d1db-b465-4764-99e1-ecedad03b06a",
				"b372d1db-b465-4764-99e1-ecedad03b06a",
				target,
				"testBundleHash",
			)
			assert.ErrorContains(t, err, tc.expectedError)
		})
	}
}

//go:embed fake.json
var fakeResponse []byte

func TestAnalysis_RunAnalysis(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, logger := setup(t)

	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans?version=2024-02-16~experimental" &&
			req.Method == "POST"
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusCreated,
		Header: http.Header{
			"Content-Type": []string{"application/vnd.api+json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"data":{"id": "a6fb2742-b67f-4dc3-bb27-42b67f1dc344"}}`))),
	}, nil)

	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans/a6fb2742-b67f-4dc3-bb27-42b67f1dc344?version=2024-02-16~experimental" &&
			req.Method == "GET"
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/vnd.api+json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"data":{"attributes": {"status": "done", "components":[{"findings_url": "http://findings_url"}]}, "id": "a6fb2742-b67f-4dc3-bb27-42b67f1dc344"}}`))),
	}, nil)

	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://findings_url" &&
			req.Method == "GET"
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(fakeResponse)),
	}, nil)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
	analysis.WithTimeoutInSeconds(120 * time.Second)
	actual, err := analysisOrchestrator.RunAnalysis(context.Background(), "b6fc8954-5918-45ce-bc89-54591815ce1b", "c172d1db-b465-4764-99e1-ecedad03b06a")

	require.NoError(t, err)
	assert.Equal(t, "scripts/db/migrations/20230811153738_add_generated_grouping_columns_to_collections_table.ts", actual.Sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI)
}

func TestAnalysis_RunAnalysis_TriggerFunctionError(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, logger := setup(t)
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans?version=2024-02-16~experimental" &&
			req.Method == "POST"
	})).Times(1).Return(nil, errors.New("error"))

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
	_, err := analysisOrchestrator.RunAnalysis(context.Background(), "b6fc8954-5918-45ce-bc89-54591815ce1b", "c172d1db-b465-4764-99e1-ecedad03b06a")
	assert.ErrorContains(t, err, "error")
}

func TestAnalysis_RunAnalysis_TriggerFunctionErrorCodes(t *testing.T) {
	type testCase struct {
		name           string
		expectedStatus int
		expectedError  string
	}

	testCases := []testCase{
		{
			name:           "StatusBadRequest",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "400",
		},
		{
			name:           "StatusUnauthorized",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "401",
		},
		{
			name:           "StatusForbidden",
			expectedStatus: http.StatusForbidden,
			expectedError:  "403",
		},
		{
			name:           "StatusNotFound",
			expectedStatus: http.StatusNotFound,
			expectedError:  "404",
		},
		{
			name:           "StatusTooManyRequests",
			expectedStatus: http.StatusTooManyRequests,
			expectedError:  "429",
		},
		{
			name:           "StatusInternalServerError",
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "500",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, logger := setup(t)

			mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
				req := i.(*http.Request)
				return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans?version=2024-02-16~experimental" &&
					req.Method == "POST"
			})).Times(1).Return(nil, errors.New(strconv.Itoa(tc.expectedStatus)))

			analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
			_, err := analysisOrchestrator.RunAnalysis(context.Background(), "b6fc8954-5918-45ce-bc89-54591815ce1b", "c172d1db-b465-4764-99e1-ecedad03b06a")
			assert.ErrorContains(t, err, tc.expectedError)
		})
	}
}

func TestAnalysis_RunAnalysis_PollingFunctionError(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, logger := setup(t)
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans?version=2024-02-16~experimental" &&
			req.Method == "POST"
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusCreated,
		Header: http.Header{
			"Content-Type": []string{"application/vnd.api+json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"data":{"id": "a6fb2742-b67f-4dc3-bb27-42b67f1dc344"}}`))),
	}, nil)

	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans/a6fb2742-b67f-4dc3-bb27-42b67f1dc344?version=2024-02-16~experimental" &&
			req.Method == "GET"
	})).Times(1).Return(nil, errors.New("error"))

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
	_, err := analysisOrchestrator.RunAnalysis(context.Background(), "b6fc8954-5918-45ce-bc89-54591815ce1b", "c172d1db-b465-4764-99e1-ecedad03b06a")
	assert.ErrorContains(t, err, "error")
}

func TestAnalysis_RunAnalysis_PollingFunctionErrorCodes(t *testing.T) {
	type testCase struct {
		name           string
		expectedStatus int
		expectedError  string
	}

	testCases := []testCase{
		{
			name:           "StatusBadRequest",
			expectedStatus: http.StatusBadRequest,
			expectedError:  "400",
		},
		{
			name:           "StatusUnauthorized",
			expectedStatus: http.StatusUnauthorized,
			expectedError:  "401",
		},
		{
			name:           "StatusForbidden",
			expectedStatus: http.StatusForbidden,
			expectedError:  "403",
		},
		{
			name:           "StatusNotFound",
			expectedStatus: http.StatusNotFound,
			expectedError:  "404",
		},
		{
			name:           "StatusTooManyRequests",
			expectedStatus: http.StatusTooManyRequests,
			expectedError:  "429",
		},
		{
			name:           "StatusInternalServerError",
			expectedStatus: http.StatusInternalServerError,
			expectedError:  "500",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, logger := setup(t)

			mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
				req := i.(*http.Request)
				return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans?version=2024-02-16~experimental" &&
					req.Method == "POST"
			})).Times(1).Return(&http.Response{
				StatusCode: http.StatusCreated,
				Header: http.Header{
					"Content-Type": []string{"application/vnd.api+json"},
				},
				Body: io.NopCloser(bytes.NewReader([]byte(`{"data":{"id": "a6fb2742-b67f-4dc3-bb27-42b67f1dc344"}}`))),
			}, nil)

			mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
				req := i.(*http.Request)
				return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans/a6fb2742-b67f-4dc3-bb27-42b67f1dc344?version=2024-02-16~experimental" &&
					req.Method == "GET"
			})).Times(1).Return(nil, errors.New(strconv.Itoa(tc.expectedStatus)))

			analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
			_, err := analysisOrchestrator.RunAnalysis(context.Background(), "b6fc8954-5918-45ce-bc89-54591815ce1b", "c172d1db-b465-4764-99e1-ecedad03b06a")
			assert.ErrorContains(t, err, tc.expectedError)
		})
	}
}

func TestAnalysis_RunAnalysis_PollingFunctionTimeout(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, logger := setup(t)

	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans?version=2024-02-16~experimental" &&
			req.Method == "POST"
	})).Return(&http.Response{
		StatusCode: http.StatusCreated,
		Header: http.Header{
			"Content-Type": []string{"application/vnd.api+json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"data":{"id": "a6fb2742-b67f-4dc3-bb27-42b67f1dc344"}}`))),
	}, nil)

	// overall 1 * 1 second, so leads to timeout
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans/a6fb2742-b67f-4dc3-bb27-42b67f1dc344?version=2024-02-16~experimental" &&
			req.Method == "GET"
	})).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/vnd.api+json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"data":{"attributes": {"status": "in_progress"}, "id": "a6fb2742-b67f-4dc3-bb27-42b67f1dc344"}}`))),
	}, nil)
	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		&logger,
		mockHTTPClient,
		mockInstrumentor,
		mockErrorReporter,
		analysis.WithTimeoutInSeconds(1*time.Second),
	)
	_, err := analysisOrchestrator.RunAnalysis(context.Background(), "b6fc8954-5918-45ce-bc89-54591815ce1b", "c172d1db-b465-4764-99e1-ecedad03b06a")
	assert.ErrorContains(t, err, "timeout requesting the ScanJobResult")
}

func TestAnalysis_RunAnalysis_GetFindingsError(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, logger := setup(t)

	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans?version=2024-02-16~experimental" &&
			req.Method == "POST"
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusCreated,
		Header: http.Header{
			"Content-Type": []string{"application/vnd.api+json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"data":{"id": "a6fb2742-b67f-4dc3-bb27-42b67f1dc344"}}`))),
	}, nil)

	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans/a6fb2742-b67f-4dc3-bb27-42b67f1dc344?version=2024-02-16~experimental" &&
			req.Method == "GET"
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/vnd.api+json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"data":{"attributes": {"status": "done", "components":[{"findings_url": "http://findings_url"}]}, "id": "a6fb2742-b67f-4dc3-bb27-42b67f1dc344"}}`))),
	}, nil)

	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://findings_url" &&
			req.Method == "GET"
	})).Times(1).Return(nil, errors.New("error"))

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
	_, err := analysisOrchestrator.RunAnalysis(context.Background(), "b6fc8954-5918-45ce-bc89-54591815ce1b", "c172d1db-b465-4764-99e1-ecedad03b06a")
	require.ErrorContains(t, err, "error")
}
func TestAnalysis_RunAnalysis_GetFindingsNotSuccessful(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, logger := setup(t)

	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans?version=2024-02-16~experimental" &&
			req.Method == "POST"
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusCreated,
		Header: http.Header{
			"Content-Type": []string{"application/vnd.api+json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"data":{"id": "a6fb2742-b67f-4dc3-bb27-42b67f1dc344"}}`))),
	}, nil)

	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://localhost/rest/orgs/b6fc8954-5918-45ce-bc89-54591815ce1b/scans/a6fb2742-b67f-4dc3-bb27-42b67f1dc344?version=2024-02-16~experimental" &&
			req.Method == "GET"
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/vnd.api+json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{"data":{"attributes": {"status": "done", "components":[{"findings_url": "http://findings_url"}]}, "id": "a6fb2742-b67f-4dc3-bb27-42b67f1dc344"}}`))),
	}, nil)

	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://findings_url" &&
			req.Method == "GET"
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusInternalServerError,
		Body:       io.NopCloser(bytes.NewReader([]byte{})),
	}, nil)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
	_, err := analysisOrchestrator.RunAnalysis(context.Background(), "b6fc8954-5918-45ce-bc89-54591815ce1b", "c172d1db-b465-4764-99e1-ecedad03b06a")
	require.ErrorContains(t, err, "failed to retrieve findings from findings URL")
}
