/*
 * © 2026 Snyk Limited All rights reserved.
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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	openapi_types "github.com/oapi-codegen/runtime/types"
	mocks2 "github.com/snyk/code-client-go/bundle/mocks"
	confMocks "github.com/snyk/code-client-go/config/mocks"
	httpmocks "github.com/snyk/code-client-go/http/mocks"
	"github.com/snyk/code-client-go/internal/analysis"
	testApi "github.com/snyk/code-client-go/internal/api/test/2025-04-07"
	externalRef0 "github.com/snyk/code-client-go/internal/api/test/2025-04-07/common"
	testModels "github.com/snyk/code-client-go/internal/api/test/2025-04-07/models"
	"github.com/snyk/code-client-go/scan"
	trackerMocks "github.com/snyk/code-client-go/scan/mocks"
)

func mockDiscoverTestCreated(t *testing.T, mockHTTP *httpmocks.MockHTTPClient, testID uuid.UUID, orgID string) {
	t.Helper()
	response := testApi.NewTestResponse()
	response.Data.Id = testID
	body, err := json.Marshal(response)
	require.NoError(t, err)

	url := fmt.Sprintf("http://localhost/hidden/orgs/%s/tests?version=%s", orgID, testApi.ApiVersion)
	mockHTTP.EXPECT().Do(mock.MatchedBy(func(i any) bool {
		req := i.(*http.Request)
		return req.Method == http.MethodPost && req.URL.String() == url
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusCreated,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil)
}

func mockDiscoverTestCompleted(t *testing.T, mockHTTP *httpmocks.MockHTTPClient, testID uuid.UUID, orgID string) {
	t.Helper()
	response := testModels.TestResult{
		Data: struct {
			Attributes testModels.TestState          `json:"attributes"`
			Id         openapi_types.UUID            `json:"id"`
			Type       testModels.TestResultDataType `json:"type"`
		}{
			Id:   testID,
			Type: testModels.TestResultDataTypeTest,
		},
		Jsonapi: externalRef0.JsonApi{Version: "1.0"},
		Links:   externalRef0.SelfLink{Self: &externalRef0.LinkProperty{}},
	}
	completed := map[string]any{
		"created_at": time.Now().Format(time.RFC3339),
		"status":     "completed",
		"result":     "passed",
	}
	stateBytes, err := json.Marshal(completed)
	require.NoError(t, err)
	response.Data.Attributes = testModels.TestState{}
	require.NoError(t, response.Data.Attributes.UnmarshalJSON(stateBytes))
	body, err := json.Marshal(response)
	require.NoError(t, err)

	url := fmt.Sprintf("http://localhost/hidden/orgs/%s/tests/%s?version=%s", orgID, testID, testApi.ApiVersion)
	mockHTTP.EXPECT().Do(mock.MatchedBy(func(i any) bool {
		req := i.(*http.Request)
		return req.Method == http.MethodGet && req.URL.String() == url
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil)
}

func mockDiscoverComponents(t *testing.T, mockHTTP *httpmocks.MockHTTPClient, testID uuid.UUID, orgID, documentPath string) {
	t.Helper()
	state := testApi.NewGetComponentsState()
	state.Data[0].Attributes.Type = string(testModels.SanitizerDiscovery)
	state.Data[0].Attributes.Success = true
	state.Data[0].Attributes.FindingsDocumentPath = &documentPath
	docType := testModels.CustomSanitizerDiscoveryDocument
	state.Data[0].Attributes.FindingsDocumentType = &docType
	body, err := json.Marshal(state)
	require.NoError(t, err)

	url := fmt.Sprintf("http://localhost/hidden/orgs/%s/tests/%s/components?version=%s", orgID, testID, testApi.ApiVersion)
	mockHTTP.EXPECT().Do(mock.MatchedBy(func(i any) bool {
		req := i.(*http.Request)
		return req.Method == http.MethodGet && req.URL.String() == url
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
	}, nil)
}

func mockDiscoverBlob(t *testing.T, mockHTTP *httpmocks.MockHTTPClient, documentPath string, payload []byte) {
	t.Helper()
	url := fmt.Sprintf("http://localhost/hidden%s?version=%s", documentPath, testApi.DocumentApiVersion)
	mockHTTP.EXPECT().Do(mock.MatchedBy(func(i any) bool {
		req := i.(*http.Request)
		return req.Method == http.MethodGet && req.URL.String() == url
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(payload)),
	}, nil)
}

func TestRunDiscoverTest_happyPath(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockHTTP := httpmocks.NewMockHTTPClient(ctrl)
	mockCfg := confMocks.NewMockConfig(ctrl)
	mockCfg.EXPECT().SnykApi().AnyTimes().Return("http://localhost")
	mockCfg.EXPECT().SnykCodeAnalysisTimeout().AnyTimes().Return(30 * time.Second)

	mockTracker := trackerMocks.NewMockTracker(ctrl)
	mockTracker.EXPECT().Begin(gomock.Any(), gomock.Any())
	mockTracker.EXPECT().End("Discovery completed.")
	mockTrackerFactory := trackerMocks.NewMockTrackerFactory(ctrl)
	mockTrackerFactory.EXPECT().GenerateTracker().Return(mockTracker)

	orgID := uuid.New().String()
	testID := uuid.New()
	documentPath := fmt.Sprintf("/orgs/%s/tests/%s/documents/%s/blob", orgID, testID, uuid.New())
	candidates := []byte(`{"scan_id":"fp","candidates":[{"kind":"sanitizer","fqn":"app.security.clean"}]}`)

	mockDiscoverTestCreated(t, mockHTTP, testID, orgID)
	mockDiscoverTestCompleted(t, mockHTTP, testID, orgID)
	mockDiscoverComponents(t, mockHTTP, testID, orgID, documentPath)
	mockDiscoverBlob(t, mockHTTP, documentPath, candidates)

	mockBundle := mocks2.NewMockBundle(ctrl)
	mockBundle.EXPECT().GetBundleHash().AnyTimes().Return("bundle-hash")
	mockBundle.EXPECT().GetLimitToFiles().AnyTimes().Return([]string{})

	target, err := scan.NewRepositoryTarget("../mypath/")
	require.NoError(t, err)

	o := analysis.NewAnalysisOrchestrator(
		mockCfg,
		mockHTTP,
		analysis.WithTrackerFactory(mockTrackerFactory),
	)

	doc, err := o.RunDiscoverTest(context.Background(), orgID, mockBundle, target)
	require.NoError(t, err)
	require.Len(t, doc.Candidates, 1)
	assert.Equal(t, "app.security.clean", doc.Candidates[0].FQN)
}

func TestRunDiscoverTest_createReject(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockHTTP := httpmocks.NewMockHTTPClient(ctrl)
	mockCfg := confMocks.NewMockConfig(ctrl)
	mockCfg.EXPECT().SnykApi().AnyTimes().Return("http://localhost")
	mockCfg.EXPECT().SnykCodeAnalysisTimeout().AnyTimes().Return(30 * time.Second)

	mockTracker := trackerMocks.NewMockTracker(ctrl)
	mockTracker.EXPECT().Begin(gomock.Any(), gomock.Any())
	mockTracker.EXPECT().End("Discovery failed.")
	mockTrackerFactory := trackerMocks.NewMockTrackerFactory(ctrl)
	mockTrackerFactory.EXPECT().GenerateTracker().Return(mockTracker)

	orgID := uuid.New().String()
	url := fmt.Sprintf("http://localhost/hidden/orgs/%s/tests?version=%s", orgID, testApi.ApiVersion)
	mockHTTP.EXPECT().Do(mock.MatchedBy(func(i any) bool {
		req := i.(*http.Request)
		return req.Method == http.MethodPost && req.URL.String() == url
	})).Times(1).Return(&http.Response{
		StatusCode: http.StatusUnprocessableEntity,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"errors":[]}`))),
	}, nil)

	mockBundle := mocks2.NewMockBundle(ctrl)
	mockBundle.EXPECT().GetBundleHash().AnyTimes().Return("bundle-hash")
	mockBundle.EXPECT().GetLimitToFiles().AnyTimes().Return([]string{})

	target, err := scan.NewRepositoryTarget("../mypath/")
	require.NoError(t, err)

	o := analysis.NewAnalysisOrchestrator(mockCfg, mockHTTP, analysis.WithTrackerFactory(mockTrackerFactory))
	_, err = o.RunDiscoverTest(context.Background(), orgID, mockBundle, target)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "422")
}
