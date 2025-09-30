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
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	openapi_types "github.com/oapi-codegen/runtime/types"
	mocks2 "github.com/snyk/code-client-go/bundle/mocks"
	confMocks "github.com/snyk/code-client-go/config/mocks"
	httpmocks "github.com/snyk/code-client-go/http/mocks"
	"github.com/snyk/code-client-go/internal/analysis"
	v20250407 "github.com/snyk/code-client-go/internal/api/test/2025-04-07"
	externalRef0 "github.com/snyk/code-client-go/internal/api/test/2025-04-07/common"
	v20250407Models "github.com/snyk/code-client-go/internal/api/test/2025-04-07/models"
	"github.com/snyk/code-client-go/observability/mocks"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
	trackerMocks "github.com/snyk/code-client-go/scan/mocks"
)

func mockDeriveErrorFromStatusCode(statusCode int) error {
	if statusCode >= http.StatusOK && statusCode < http.StatusBadRequest {
		return nil
	}

	return fmt.Errorf("Statuscode: %d", statusCode)
}

func mockTestStatusResponse(t *testing.T, mockHTTPClient *httpmocks.MockHTTPClient, orgId string, testId uuid.UUID, responseCode int) {
	t.Helper()

	response := v20250407Models.TestResult{
		Data: struct {
			Attributes v20250407Models.TestState          `json:"attributes"`
			Id         openapi_types.UUID                 `json:"id"`
			Type       v20250407Models.TestResultDataType `json:"type"`
		}{
			Id:   testId,
			Type: v20250407Models.TestResultDataTypeTest,
		},
		Jsonapi: externalRef0.JsonApi{Version: "1.0"},
		Links:   externalRef0.SelfLink{Self: &externalRef0.LinkProperty{}},
	}

	completedStateJSON := map[string]interface{}{
		"created_at": time.Now().Format(time.RFC3339),
		"status":     "completed",
		"result":     "passed",
	}

	stateBytes, err := json.Marshal(completedStateJSON)
	assert.NoError(t, err)
	response.Data.Attributes = v20250407Models.TestState{}
	err = response.Data.Attributes.UnmarshalJSON(stateBytes)
	assert.NoError(t, err)

	responseBodyBytes, err := json.Marshal(response)
	assert.NoError(t, err)

	expectedTestStatusUrl := fmt.Sprintf("http://localhost/hidden/orgs/%s/tests/%s?version=%s", orgId, testId, v20250407.ApiVersion)
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == expectedTestStatusUrl && req.Method == http.MethodGet
	})).Times(1).Return(&http.Response{
		StatusCode: responseCode,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(responseBodyBytes)),
	}, mockDeriveErrorFromStatusCode(responseCode))
}

func mockGetComponentResponse(t *testing.T, sarifResponse sarif.SarifDocument, expectedDocumentPath string, mockHTTPClient *httpmocks.MockHTTPClient, responseCode int) {
	t.Helper()
	responseBodyBytes, err := json.Marshal(sarifResponse)
	assert.NoError(t, err)
	expectedDocumentUrl := fmt.Sprintf("http://localhost/hidden%s?version=%s", expectedDocumentPath, v20250407.DocumentApiVersion)
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == expectedDocumentUrl
	})).Times(1).Return(&http.Response{
		StatusCode: responseCode,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(responseBodyBytes)),
	}, mockDeriveErrorFromStatusCode(responseCode))
}

func mockResultCompletedResponse(t *testing.T, mockHTTPClient *httpmocks.MockHTTPClient, expectedWebuilink string, projectId uuid.UUID, snapshotId uuid.UUID, orgId string, testId uuid.UUID, documentPath string, responseCode int) {
	t.Helper()
	state := v20250407.NewGetComponentsState()
	state.Data[0].Attributes.Type = "sast"
	state.Data[0].Attributes.FindingsDocumentPath = &documentPath
	findingsDocumentType := v20250407Models.Sarif
	state.Data[0].Attributes.FindingsDocumentType = &findingsDocumentType
	state.Data[0].Attributes.Success = true
	state.Data[0].Attributes.Webui = &v20250407Models.WebUI{
		Link:       &expectedWebuilink,
		ProjectId:  &projectId,
		SnapshotId: &snapshotId,
	}
	responseBodyBytes, err := json.Marshal(state)
	assert.NoError(t, err)
	expectedRetrieveTestUrl := fmt.Sprintf("http://localhost/hidden/orgs/%s/tests/%s/components?version=%s", orgId, testId, v20250407.ApiVersion)
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		return req.URL.String() == expectedRetrieveTestUrl
	})).Times(1).Return(&http.Response{
		StatusCode: responseCode,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(responseBodyBytes)),
	}, mockDeriveErrorFromStatusCode(responseCode))
}

func mockTestCreatedResponse(t *testing.T, mockHTTPClient *httpmocks.MockHTTPClient, testId uuid.UUID, orgId string, responseCode int) {
	t.Helper()
	response := v20250407.NewTestResponse()
	response.Data.Id = testId
	responseBodyBytes, err := json.Marshal(response)
	assert.NoError(t, err)
	expectedTestCreatedUrl := fmt.Sprintf("http://localhost/hidden/orgs/%s/tests?version=%s", orgId, v20250407.ApiVersion)
	mockHTTPClient.EXPECT().Do(mock.MatchedBy(func(i interface{}) bool {
		req := i.(*http.Request)
		validateTestRequestBody(t, req.Body)

		return req.URL.String() == expectedTestCreatedUrl &&
			req.Method == http.MethodPost
	})).Times(1).Return(&http.Response{
		StatusCode: responseCode,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(responseBodyBytes)),
	}, mockDeriveErrorFromStatusCode(responseCode))
}

func validateTestRequestBody(t *testing.T, request io.Reader) {
	t.Helper()
	body, _ := io.ReadAll(request)
	var testRequestBody v20250407Models.CreateTestRequestBody
	err := json.Unmarshal(body, &testRequestBody)
	assert.NoError(t, err)
	bundle, err := testRequestBody.Data.Attributes.Input.AsTestInputSourceBundle()
	assert.NoError(t, err)

	if bundle.Metadata.CommitId != nil {
		assert.Regexp(t, "^[0-9a-f]{40}$", *bundle.Metadata.CommitId)
	}
	if bundle.Metadata.RepoUrl != nil {
		assert.Regexp(t, "^git@github.com:[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+.git$", *bundle.Metadata.RepoUrl)
	}
}

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

func TestAnalysis_RunTest(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, mockTracker, mockTrackerFactory, logger := setup(t, nil)
	mockTracker.EXPECT().Begin(gomock.Eq("Snyk Code analysis for ../mypath/"), gomock.Eq("Retrieving results...")).Return()
	mockTracker.EXPECT().End(gomock.Eq("Analysis completed.")).Return()

	orgId := "4a72d1db-b465-4764-99e1-ecedad03b06a"
	projectId := uuid.New()
	snapshotId := uuid.New()
	testId := uuid.New()
	report := true
	inputBundle := mocks2.NewMockBundle(ctrl)
	targetId, err := scan.NewRepositoryTarget("../mypath/")
	assert.NoError(t, err)

	inputBundle.EXPECT().GetBundleHash().Return("").AnyTimes()
	inputBundle.EXPECT().GetLimitToFiles().Return([]string{}).AnyTimes()

	// Test Created Response
	mockTestCreatedResponse(t, mockHTTPClient, testId, orgId, http.StatusCreated)

	// Test Status Response
	mockTestStatusResponse(t, mockHTTPClient, orgId, testId, http.StatusOK)

	// Get Test Result Response
	expectedWebuilink := ""
	expectedDocumentPath := "/1234"
	mockResultCompletedResponse(t, mockHTTPClient, expectedWebuilink, projectId, snapshotId, orgId, testId, expectedDocumentPath, http.StatusOK)

	// get document
	sarifResponse := sarif.SarifDocument{
		Version: "42.0",
	}

	mockGetComponentResponse(t, sarifResponse, expectedDocumentPath, mockHTTPClient, http.StatusOK)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	result, resultMetadata, err := analysisOrchestrator.RunTest(
		t.Context(),
		orgId,
		inputBundle,
		targetId,
		analysis.AnalysisConfig{
			Report: report,
		},
	)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, resultMetadata)
	assert.Equal(t, expectedWebuilink, resultMetadata.WebUiUrl)
	assert.Equal(t, projectId.String(), resultMetadata.ProjectId)
	assert.Equal(t, snapshotId.String(), resultMetadata.SnapshotId)
	assert.Equal(t, sarifResponse.Version, result.Sarif.Version)
}

func TestAnalysis_RunTestRemote(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, mockTracker, mockTrackerFactory, logger := setup(t, nil)
	mockTracker.EXPECT().Begin(gomock.Eq("Snyk Code analysis for remote project"), gomock.Eq("Retrieving results...")).Return()
	mockTracker.EXPECT().End(gomock.Eq("Analysis completed.")).Return()

	orgId := "4a72d1db-b465-4764-99e1-ecedad03b06a"
	projectId := uuid.New()
	snapshotId := uuid.New()
	testId := uuid.New()
	commitId := "abc123"
	report := true

	// Test Created Response
	mockTestCreatedResponse(t, mockHTTPClient, testId, orgId, http.StatusCreated)

	// Test Status Response
	mockTestStatusResponse(t, mockHTTPClient, orgId, testId, http.StatusOK)

	// Get Test Result Response
	expectedWebuilink := ""
	expectedDocumentPath := "/1234"
	mockResultCompletedResponse(t, mockHTTPClient, expectedWebuilink, projectId, snapshotId, orgId, testId, expectedDocumentPath, http.StatusOK)

	// get document
	sarifResponse := sarif.SarifDocument{
		Version: "42.0",
	}
	mockGetComponentResponse(t, sarifResponse, expectedDocumentPath, mockHTTPClient, http.StatusOK)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	result, resultMetadata, err := analysisOrchestrator.RunTestRemote(
		t.Context(),
		orgId,
		analysis.AnalysisConfig{
			ProjectId: &projectId,
			CommitId:  &commitId,
			Report:    report,
		},
	)

	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, resultMetadata)
	assert.Equal(t, expectedWebuilink, resultMetadata.WebUiUrl)
	assert.Equal(t, projectId.String(), resultMetadata.ProjectId)
	assert.Equal(t, snapshotId.String(), resultMetadata.SnapshotId)
	assert.Equal(t, sarifResponse.Version, result.Sarif.Version)
}

func TestAnalysis_RunTestRemote_CreateTestFailed(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, mockTracker, mockTrackerFactory, logger := setup(t, nil)
	mockTracker.EXPECT().Begin(gomock.Eq("Snyk Code analysis for remote project"), gomock.Eq("Retrieving results...")).Return()
	mockTracker.EXPECT().End(gomock.Eq("Analysis failed.")).Return()

	orgId := "4a72d1db-b465-4764-99e1-ecedad03b06a"
	projectId := uuid.New()
	testId := uuid.New()
	commitId := "abc123"
	report := true

	// Test Created Response
	mockTestCreatedResponse(t, mockHTTPClient, testId, orgId, http.StatusInternalServerError)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	result, resultMetadata, err := analysisOrchestrator.RunTestRemote(
		t.Context(),
		orgId,
		analysis.AnalysisConfig{
			ProjectId: &projectId,
			CommitId:  &commitId,
			Report:    report,
		},
	)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Nil(t, resultMetadata)
}

func TestAnalysis_RunTestRemote_PollingFailed(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, mockTracker, mockTrackerFactory, logger := setup(t, nil)
	mockTracker.EXPECT().Begin(gomock.Eq("Snyk Code analysis for remote project"), gomock.Eq("Retrieving results...")).Return()
	mockTracker.EXPECT().End(gomock.Eq("Analysis failed.")).Return()

	orgId := "4a72d1db-b465-4764-99e1-ecedad03b06a"
	projectId := uuid.New()
	testId := uuid.New()
	commitId := "abc123"
	report := true

	// Test Created Response
	mockTestCreatedResponse(t, mockHTTPClient, testId, orgId, http.StatusCreated)

	// Test Status Response
	mockTestStatusResponse(t, mockHTTPClient, orgId, testId, http.StatusOK)

	// Get Test Result Response
	expectedWebuilink := ""
	expectedDocumentPath := "/1234"
	mockResultCompletedResponse(t, mockHTTPClient, expectedWebuilink, projectId, uuid.New(), orgId, testId, expectedDocumentPath, http.StatusInternalServerError)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	result, resultMetadata, err := analysisOrchestrator.RunTestRemote(
		t.Context(),
		orgId,
		analysis.AnalysisConfig{
			ProjectId: &projectId,
			CommitId:  &commitId,
			Report:    report,
		},
	)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Nil(t, resultMetadata)
}

func TestAnalysis_RunTestRemote_GetDocumentFailed(t *testing.T) {
	mockConfig, mockHTTPClient, mockInstrumentor, mockErrorReporter, mockTracker, mockTrackerFactory, logger := setup(t, nil)
	mockTracker.EXPECT().Begin(gomock.Eq("Snyk Code analysis for remote project"), gomock.Eq("Retrieving results...")).Return()
	mockTracker.EXPECT().End(gomock.Eq("Analysis failed.")).Return()

	orgId := "4a72d1db-b465-4764-99e1-ecedad03b06a"
	projectId := uuid.New()
	testId := uuid.New()
	commitId := "abc123"
	report := true

	// Test Created Response
	mockTestCreatedResponse(t, mockHTTPClient, testId, orgId, http.StatusCreated)

	// Test Status Response
	mockTestStatusResponse(t, mockHTTPClient, orgId, testId, http.StatusOK)

	// Get Test Result Response
	expectedWebuilink := ""
	expectedDocumentPath := "/1234"
	mockResultCompletedResponse(t, mockHTTPClient, expectedWebuilink, projectId, uuid.New(), orgId, testId, expectedDocumentPath, http.StatusOK)

	// get document
	sarifResponse := sarif.SarifDocument{
		Version: "42.0",
	}
	mockGetComponentResponse(t, sarifResponse, expectedDocumentPath, mockHTTPClient, http.StatusInternalServerError)

	analysisOrchestrator := analysis.NewAnalysisOrchestrator(
		mockConfig,
		mockHTTPClient,
		analysis.WithLogger(&logger),
		analysis.WithInstrumentor(mockInstrumentor),
		analysis.WithTrackerFactory(mockTrackerFactory),
		analysis.WithErrorReporter(mockErrorReporter),
	)

	// run method under test
	result, resultMetadata, err := analysisOrchestrator.RunTestRemote(
		t.Context(),
		orgId,
		analysis.AnalysisConfig{
			ProjectId: &projectId,
			CommitId:  &commitId,
			Report:    report,
		},
	)

	require.Error(t, err)
	assert.Nil(t, result)
	assert.Nil(t, resultMetadata)
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
			t.Context(),
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
			t.Context(),
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
			t.Context(),
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
