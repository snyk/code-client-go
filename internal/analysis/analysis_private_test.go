package analysis

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	confMocks "github.com/snyk/code-client-go/config/mocks"
	httpmocks "github.com/snyk/code-client-go/http/mocks"
	testApi "github.com/snyk/code-client-go/internal/api/test/2025-04-07"
	"github.com/snyk/error-catalog-golang-public/snyk_errors"
	"github.com/stretchr/testify/assert"
)

func TestAnalysis_retrieveTestURL_TestResultError(t *testing.T) {
	ctrl := gomock.NewController(t)
	config := confMocks.NewMockConfig(ctrl)
	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)
	apiClient, err := testApi.NewClient("http://localhost", testApi.WithHTTPClient(mockHTTPClient))
	assert.NoError(t, err)

	analysisOrchestrator, ok := NewAnalysisOrchestrator(
		config,
		mockHTTPClient,
	).(*analysisOrchestrator)

	assert.True(t, ok)

	mockHTTPClient.EXPECT().Do(gomock.Any()).Return(&http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewBufferString(`{
    "data": {
        "id": "8afb6fed-b2a9-48cd-9097-8cebd80935e2",
        "type": "test",
        "attributes": {
            "status": "error",
            "created_at": "2025-10-09T08:42:07.462607Z",
            "errors": [
                {
                    "title": "Analysis result size limit exceeded",
                    "classification": "UNSUPPORTED",
                    "message": "Analysis result sarif size is too large",
                    "error_code": "SNYK-CODE-0002",
                    "info_url": "https://docs.snyk.io/scan-with-snyk/error-catalog#snyk-code-0002"
                }
            ]
        }
    },
    "jsonapi": {
        "version": "1.0"
    },
    "links": {
        "self": "/hidden/orgs/***/tests/8afb6fed-b2a9-48cd-9097-8cebd80935e2"
    }
}`)),
	}, nil)

	resultMetaData, completed, err := analysisOrchestrator.retrieveTestURL(t.Context(), apiClient, uuid.New(), uuid.New())
	assert.Error(t, err)
	assert.False(t, completed)
	assert.Nil(t, resultMetaData)

	expectedError := snyk_errors.Error{}
	assert.ErrorAs(t, err, &expectedError)
	assert.Equal(t, expectedError.ErrorCode, "SNYK-CODE-0002")
	assert.Equal(t, expectedError.Title, "Analysis result size limit exceeded")
	assert.Equal(t, expectedError.Detail, "Analysis result sarif size is too large")
	assert.Equal(t, expectedError.Classification, "UNSUPPORTED")
	assert.Equal(t, expectedError.Type, "https://docs.snyk.io/scan-with-snyk/error-catalog#snyk-code-0002")
}
