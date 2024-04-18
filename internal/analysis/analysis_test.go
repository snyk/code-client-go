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
	"fmt"
	"github.com/stretchr/testify/mock"
	"io"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	confMocks "github.com/snyk/code-client-go/config/mocks"
	httpmocks "github.com/snyk/code-client-go/http/mocks"
	"github.com/snyk/code-client-go/internal/analysis"
	"github.com/snyk/code-client-go/observability/mocks"
	"github.com/snyk/code-client-go/sarif"
)

func TestAnalysis_CreateWorkspace(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockSpan.EXPECT().Context().AnyTimes()
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().Organization().AnyTimes().Return("")
	mockConfig.EXPECT().SnykApi().AnyTimes().Return("http://localhost")

	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)
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

	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
	mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

	logger := zerolog.Nop()

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
	_, err := analysisOrchestrator.CreateWorkspace(
		context.Background(),
		"4a72d1db-b465-4764-99e1-ecedad03b06a",
		"b372d1db-b465-4764-99e1-ecedad03b06a",
		"../../",
		"testBundleHash")
	assert.NoError(t, err)
}

func TestAnalysis_CreateWorkspace_NotARepository(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockSpan.EXPECT().Context().AnyTimes()
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().SnykCodeApi().AnyTimes().Return("http://localhost")

	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)

	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).Times(1)
	mockInstrumentor.EXPECT().Finish(gomock.Any()).Times(1)
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
	mockErrorReporter.EXPECT().CaptureError(gomock.Any(), gomock.Any())

	logger := zerolog.Nop()

	repoDir := t.TempDir()
	analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
	_, err := analysisOrchestrator.CreateWorkspace(
		context.Background(),
		"4a72d1db-b465-4764-99e1-ecedad03b06a",
		"b372d1db-b465-4764-99e1-ecedad03b06a",
		repoDir,
		"testBundleHash",
	)
	assert.ErrorContains(t, err, "open local repository")
}

func TestAnalysis_CreateWorkspace_Failure(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockSpan.EXPECT().Context().AnyTimes()
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().SnykApi().AnyTimes().Return("http://localhost")

	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)
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

	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
	mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

	logger := zerolog.Nop()

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
	_, err := analysisOrchestrator.CreateWorkspace(
		context.Background(),
		"4a72d1db-b465-4764-99e1-ecedad03b06a",
		"b372d1db-b465-4764-99e1-ecedad03b06a",
		"../../",
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
			mockHTTPClient.EXPECT().Do(gomock.Any()).Times(1).Return(&http.Response{
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

			analysisOrchestrator := analysis.NewAnalysisOrchestrator(&logger, mockHTTPClient, mockInstrumentor, mockErrorReporter, mockConfig)
			_, err := analysisOrchestrator.CreateWorkspace(
				context.Background(),
				"4a72d1db-b465-4764-99e1-ecedad03b06a",
				"b372d1db-b465-4764-99e1-ecedad03b06a",
				"../../",
				"testBundleHash",
			)
			assert.ErrorContains(t, err, tc.expectedError)
		})
	}
}

func TestAnalysis_RunAnalysis(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockSpan.EXPECT().Context().AnyTimes()
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().Organization().AnyTimes().Return("")
	mockConfig.EXPECT().SnykCodeApi().AnyTimes().Return("http://localhost")

	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)

	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
	mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

	logger := zerolog.Nop()

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(mockConfig, &logger, mockHTTPClient, mockInstrumentor, mockErrorReporter)
	actual, err := analysisOrchestrator.RunAnalysis()
	require.NoError(t, err)
	assert.Equal(t, "COMPLETE", actual.Status)
	assert.Contains(t, actual.Sarif.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI, "scripts/db/migrations/20230811153738_add_generated_grouping_columns_to_collections_table.ts")
	assert.Nil(t, actual.Sarif.Runs[0].Results[0].Suppressions)
	assert.NotNil(t, actual.Sarif.Runs[0].Results[1].Suppressions)
	assert.Len(t, actual.Sarif.Runs[0].Results[1].Suppressions, 1)
	assert.Equal(t, "False positive", actual.Sarif.Runs[0].Results[1].Suppressions[0].Justification)
	assert.Equal(t, sarif.WontFix, actual.Sarif.Runs[0].Results[1].Suppressions[0].Properties.Category)
	assert.Equal(t, "13 days", *actual.Sarif.Runs[0].Results[1].Suppressions[0].Properties.Expiration)
	assert.Equal(t, "2024-02-23T16:08:25Z", actual.Sarif.Runs[0].Results[1].Suppressions[0].Properties.IgnoredOn)
	assert.Equal(t, "Neil M", actual.Sarif.Runs[0].Results[1].Suppressions[0].Properties.IgnoredBy.Name)
	assert.Equal(t, "test@test.io", *actual.Sarif.Runs[0].Results[1].Suppressions[0].Properties.IgnoredBy.Email)
}
