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
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	confMocks "github.com/snyk/code-client-go/config/mocks"
	httpmocks "github.com/snyk/code-client-go/http/mocks"
	"github.com/snyk/code-client-go/internal/analysis"
	"github.com/snyk/code-client-go/observability/mocks"
	trackerMocks "github.com/snyk/code-client-go/scan/mocks"
)

func setup(t *testing.T, timeout *time.Duration) (*confMocks.MockConfig, *httpmocks.MockHTTPClient, *mocks.MockInstrumentor, *mocks.MockErrorReporter, *trackerMocks.MockTracker, *trackerMocks.MockTrackerFactory, zerolog.Logger) {
	t.Helper()
	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockSpan.EXPECT().Context().AnyTimes()
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().Organization().AnyTimes().Return("")
	mockConfig.EXPECT().SnykApi().AnyTimes().Return("http://localhost")
	if timeout == nil {
		defaultTimeout := 120 * time.Second
		timeout = &defaultTimeout
	}
	mockConfig.EXPECT().SnykCodeAnalysisTimeout().AnyTimes().Return(*timeout)

	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)

	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
	mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
	mockTracker := trackerMocks.NewMockTracker(ctrl)
	mockTrackerFactory := trackerMocks.NewMockTrackerFactory(ctrl)
	mockTrackerFactory.EXPECT().GenerateTracker().Return(mockTracker).AnyTimes()

	logger := zerolog.Nop()
	return mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, mockTracker, mockTrackerFactory, logger
}

//go:embed fake.json
var fakeResponse []byte

func TestAnalysis_RunTestRemote(t *testing.T) {
	t.Skip()
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, mockTracker, mockTrackerFactory, logger := setup(t, nil)

	mockTracker.EXPECT().Begin(gomock.Eq("Snyk Code analysis for remote project"), gomock.Eq("Retrieving results...")).Return()
	mockTracker.EXPECT().End(gomock.Eq("Analysis complete.")).Return()

	projectId := uuid.New()
	commitId := "abc123"
	report := true

	// Mock the initial test creation request
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://localhost/hidden/orgs/4a72d1db-b465-4764-99e1-ecedad03b06a/tests?version=2024-12-21" &&
			req.Method == http.MethodPost
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusCreated,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader([]byte(`{
			"data": {
				"id": "a6fb2742-b67f-4dc3-bb27-42b67f1dc344",
				"type": "test-result",
				"attributes": {
					"status": "completed",
					"documents": {
						"enriched_sarif": "/tests/123/sarif"
					}
				}
			},
			"jsonapi": {
				"version": "1.0"
			},
			"links": {
				"self": "http://localhost/hidden/orgs/4a72d1db-b465-4764-99e1-ecedad03b06a/tests/a6fb2742-b67f-4dc3-bb27-42b67f1dc344"
			}
		}`))),
	}, nil)
	// Mock the findings retrieval request
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == "http://localhost/tests/123/sarif" &&
			req.Method == http.MethodGet
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(fakeResponse)),
	}, nil)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	result, _, err := analysisOrchestrator.RunTestRemote(
		context.Background(),
		"4a72d1db-b465-4764-99e1-ecedad03b06a",
		analysis.AnalysisConfig{
			ProjectId: &projectId,
			CommitId:  &commitId,
			Report:    report,
		},
	)

	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestAnalysis_RunTestRemote_MissingRequiredParams(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, _, mockTrackerFactory, logger := setup(t, nil)
	mockHTTPClient.EXPECT().Do(gomock.Any()).Times(0)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	t.Run("missing both projectId and commitId", func(t *testing.T) {
		result, _, err := analysisOrchestrator.RunTestRemote(
			context.Background(),
			"4a72d1db-b465-4764-99e1-ecedad03b06a",
			analysis.AnalysisConfig{},
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "projectId and commitId are required")
		assert.Nil(t, result)
	})

	t.Run("missing projectId", func(t *testing.T) {
		commitId := "abc123"
		result, _, err := analysisOrchestrator.RunTestRemote(
			context.Background(),
			"4a72d1db-b465-4764-99e1-ecedad03b06a",
			analysis.AnalysisConfig{
				CommitId: &commitId,
			},
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "projectId and commitId are required")
		assert.Nil(t, result)
	})

	t.Run("missing commitId", func(t *testing.T) {
		projectId := uuid.New()
		result, _, err := analysisOrchestrator.RunTestRemote(
			context.Background(),
			"4a72d1db-b465-4764-99e1-ecedad03b06a",
			analysis.AnalysisConfig{
				ProjectId: &projectId,
			},
		)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "projectId and commitId are required")
		assert.Nil(t, result)
	})
}
