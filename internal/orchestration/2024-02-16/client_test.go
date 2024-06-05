package v20240216_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	openapi_types "github.com/oapi-codegen/runtime/types"

	scans "github.com/snyk/code-client-go/internal/orchestration/2024-02-16/scans"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	orchestrationClient "github.com/snyk/code-client-go/internal/orchestration/2024-02-16"
)

// HTTPRequestDoerMock mocks the interface HttpRequestDoerMock.
type HTTPRequestDoerMock struct {
	mock.Mock
}

func (m *HTTPRequestDoerMock) Do(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*http.Response), args.Error(1)
}

func TestOrchestration_CreateScanWorkspaceJobForUserWithApplicationVndAPIPlusJSONBody_Success(t *testing.T) {
	doer := &HTTPRequestDoerMock{}
	mockResponse := http.Response{
		Body: io.NopCloser(bytes.NewBufferString(`{
  "data": {
    "attributes": {
	  "created_at": "2017-07-21T17:32:28Z",
	  "status": "complete"
	},
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "type": "scan_job"
  },
  "jsonapi": {
    "version": "1.0"
  },
  "links": {
    "self": "https://example.com/api/this_resource"
  }
}`)),
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		StatusCode: http.StatusCreated,
	}
	doer.On("Do", mock.Anything).Return(&mockResponse, nil).Run(func(args mock.Arguments) {
		req, ok := args.Get(0).(*http.Request)
		assert.True(t, ok)
		assert.Equal(t, "https://api.snyk.io/rest/orgs/e7ea34c9-de0f-422c-bf2c-4654c2e2da90/scans?version=2024-02-16~experimental", req.URL.String())
	})
	client, err := orchestrationClient.NewClientWithResponses("https://api.snyk.io/rest", orchestrationClient.WithHTTPClient(doer))
	require.NoError(t, err)

	orgUUID := uuid.MustParse("e7ea34c9-de0f-422c-bf2c-4654c2e2da90")
	id := uuid.New()
	response, err := client.CreateScanWorkspaceJobForUserWithApplicationVndAPIPlusJSONBodyWithResponse(
		context.Background(),
		orgUUID,
		&orchestrationClient.CreateScanWorkspaceJobForUserParams{Version: "2024-02-16~experimental"},
		orchestrationClient.CreateScanWorkspaceJobForUserApplicationVndAPIPlusJSONRequestBody{Data: struct {
			Attributes struct {
				Flow scans.Flow `json:"flow"`

				// ScanOptions Additional options for the scan
				ScanOptions *struct {
					// LimitScanToFiles The findings will be limited to a subset of files only.
					LimitScanToFiles *[]string `json:"limit_scan_to_files,omitempty"`
				} `json:"scan_options,omitempty"`

				// WorkspaceId ID of the workspace to be scanned. We are migrating from URL to the ID - please send both fields until we can drop the URL.
				WorkspaceId *openapi_types.UUID `json:"workspace_id,omitempty"`

				// WorkspaceUrl The URI of the workspace to be scanned as returned by the workspace service.
				WorkspaceUrl string `json:"workspace_url"`
			} `json:"attributes"`
			Id   *openapi_types.UUID           `json:"id,omitempty"`
			Type scans.PostScanRequestDataType `json:"type"`
		}{
			Id:   &id,
			Type: "cli",
		}})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, 201, response.StatusCode())
	require.Equal(t, "3fa85f64-5717-4562-b3fc-2c963f66afa6", response.ApplicationvndApiJSON201.Data.Id.String())
	doer.AssertExpectations(t)
}

func TestOrchestration_CreateScanWorkspaceJobForUserWithApplicationVndAPIPlusJSONBody_Success_NotFound(t *testing.T) {
	doer := &HTTPRequestDoerMock{}
	mockResponse := http.Response{
		Body: io.NopCloser(bytes.NewBufferString(`{
  "errors": [],
  "jsonapi": {
    "version": "1.0"
  }
}`)),
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		StatusCode: http.StatusNotFound,
	}
	doer.On("Do", mock.Anything).Return(&mockResponse, nil).Run(func(args mock.Arguments) {
		req, ok := args.Get(0).(*http.Request)
		assert.True(t, ok)
		assert.Equal(t, "https://api.snyk.io/rest/orgs/e7ea34c9-de0f-422c-bf2c-4654c2e2da90/scans?version=2024-02-16~experimental", req.URL.String())
	})
	client, err := orchestrationClient.NewClientWithResponses("https://api.snyk.io/rest", orchestrationClient.WithHTTPClient(doer))
	require.NoError(t, err)

	orgUUID := uuid.MustParse("e7ea34c9-de0f-422c-bf2c-4654c2e2da90")
	id := uuid.New()
	response, err := client.CreateScanWorkspaceJobForUserWithApplicationVndAPIPlusJSONBodyWithResponse(
		context.Background(),
		orgUUID,
		&orchestrationClient.CreateScanWorkspaceJobForUserParams{Version: "2024-02-16~experimental"},
		orchestrationClient.CreateScanWorkspaceJobForUserApplicationVndAPIPlusJSONRequestBody{Data: struct {
			Attributes struct {
				Flow scans.Flow `json:"flow"`
				// ScanOptions Additional options for the scan
				ScanOptions *struct {
					// LimitScanToFiles The findings will be limited to a subset of files only.
					LimitScanToFiles *[]string `json:"limit_scan_to_files,omitempty"`
				} `json:"scan_options,omitempty"`

				// WorkspaceId ID of the workspace to be scanned. We are migrating from URL to the ID - please send both fields until we can drop the URL.
				WorkspaceId *openapi_types.UUID `json:"workspace_id,omitempty"`

				// WorkspaceUrl The URI of the workspace to be scanned as returned by the workspace service.
				WorkspaceUrl string `json:"workspace_url"`
			} `json:"attributes"`
			Id   *openapi_types.UUID           `json:"id,omitempty"`
			Type scans.PostScanRequestDataType `json:"type"`
		}{
			Id:   &id,
			Type: "cli",
		}})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, http.StatusNotFound, response.StatusCode())
	require.NotNil(t, response.ApplicationvndApiJSON404.Errors)
	doer.AssertExpectations(t)
}

func TestOrchestration_CreateScanWorkspaceJobForUserWithApplicationVndAPIPlusJSONBody_Failure(t *testing.T) {
	doer := &HTTPRequestDoerMock{}
	doer.On("Do", mock.Anything).Return(nil, errors.New("something went wrong")).Run(func(args mock.Arguments) {
		req, ok := args.Get(0).(*http.Request)
		assert.True(t, ok)
		assert.Equal(t, "https://api.snyk.io/rest/orgs/e7ea34c9-de0f-422c-bf2c-4654c2e2da90/scans?version=2024-02-16~experimental", req.URL.String())
	})
	client, err := orchestrationClient.NewClientWithResponses("https://api.snyk.io/rest", orchestrationClient.WithHTTPClient(doer))
	require.NoError(t, err)

	orgUUID := uuid.MustParse("e7ea34c9-de0f-422c-bf2c-4654c2e2da90")
	id := uuid.New()
	_, err = client.CreateScanWorkspaceJobForUserWithApplicationVndAPIPlusJSONBodyWithResponse(
		context.Background(),
		orgUUID,
		&orchestrationClient.CreateScanWorkspaceJobForUserParams{Version: "2024-02-16~experimental"},
		orchestrationClient.CreateScanWorkspaceJobForUserApplicationVndAPIPlusJSONRequestBody{Data: struct {
			Attributes struct {
				Flow scans.Flow `json:"flow"`

				// ScanOptions Additional options for the scan
				ScanOptions *struct {
					// LimitScanToFiles The findings will be limited to a subset of files only.
					LimitScanToFiles *[]string `json:"limit_scan_to_files,omitempty"`
				} `json:"scan_options,omitempty"`

				// WorkspaceId ID of the workspace to be scanned. We are migrating from URL to the ID - please send both fields until we can drop the URL.
				WorkspaceId *openapi_types.UUID `json:"workspace_id,omitempty"`

				// WorkspaceUrl The URI of the workspace to be scanned as returned by the workspace service.
				WorkspaceUrl string `json:"workspace_url"`
			} `json:"attributes"`
			Id   *openapi_types.UUID           `json:"id,omitempty"`
			Type scans.PostScanRequestDataType `json:"type"`
		}{
			Id:   &id,
			Type: "cli",
		}})
	require.Error(t, err)
	doer.AssertExpectations(t)
}

func TestOrchestration_GetScanWorkspaceJobForUserWithResponse_Success(t *testing.T) {
	doer := &HTTPRequestDoerMock{}
	mockResponse := http.Response{
		Body: io.NopCloser(bytes.NewBufferString(`{
  "data": {
    "attributes": {
      "components": [
        {
          "created_at": "2017-07-21T17:32:28Z",
          "findings_url": "http://findings/url",
          "id": "123e4567-e89b-12d3-a456-426655440000",
          "name": "src/main.ts",
          "type": "typescript"
        }
      ],
      "created_at": "2017-07-21T17:32:28Z",
      "status": "in_progress"
    },
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "type": "scan_job_results"
  }
}`)),
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		StatusCode: http.StatusOK,
	}
	doer.On("Do", mock.Anything).Return(&mockResponse, nil).Run(func(args mock.Arguments) {
		req, ok := args.Get(0).(*http.Request)
		assert.True(t, ok)
		assert.Equal(t, "https://api.snyk.io/rest/orgs/e7ea34c9-de0f-422c-bf2c-4654c2e2da90/scans/b23b92f8-6b3e-4daa-9f15-1083224b25d0?version=2024-02-16~experimental", req.URL.String())
	})
	client, err := orchestrationClient.NewClientWithResponses("https://api.snyk.io/rest", orchestrationClient.WithHTTPClient(doer))
	require.NoError(t, err)

	orgUUID := uuid.MustParse("e7ea34c9-de0f-422c-bf2c-4654c2e2da90")
	id := uuid.MustParse("b23b92f8-6b3e-4daa-9f15-1083224b25d0")
	response, err := client.GetScanWorkspaceJobForUserWithResponse(
		context.Background(),
		orgUUID,
		id,
		&orchestrationClient.GetScanWorkspaceJobForUserParams{Version: "2024-02-16~experimental"})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, http.StatusOK, response.StatusCode())
	require.Equal(t, scans.ScanJobResultsAttributesStatusInProgress, response.ApplicationvndApiJSON200.Data.Attributes.Status)
	doer.AssertExpectations(t)
}

func TestOrchestration_GetScanWorkspaceJobForUserWithResponse_Success_NotFound(t *testing.T) {
	doer := &HTTPRequestDoerMock{}
	mockResponse := http.Response{
		Body: io.NopCloser(bytes.NewBufferString(`{
  "errors": [],
  "jsonapi": {
    "version": "1.0"
  }
}`)),
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		StatusCode: http.StatusNotFound,
	}
	doer.On("Do", mock.Anything).Return(&mockResponse, nil).Run(func(args mock.Arguments) {
		req, ok := args.Get(0).(*http.Request)
		assert.True(t, ok)
		assert.Equal(t, "https://api.snyk.io/rest/orgs/e7ea34c9-de0f-422c-bf2c-4654c2e2da90/scans/b23b92f8-6b3e-4daa-9f15-1083224b25d0?version=2024-02-16~experimental", req.URL.String())
	})
	client, err := orchestrationClient.NewClientWithResponses("https://api.snyk.io/rest", orchestrationClient.WithHTTPClient(doer))
	require.NoError(t, err)

	orgUUID := uuid.MustParse("e7ea34c9-de0f-422c-bf2c-4654c2e2da90")
	id := uuid.MustParse("b23b92f8-6b3e-4daa-9f15-1083224b25d0")
	response, err := client.GetScanWorkspaceJobForUserWithResponse(
		context.Background(),
		orgUUID,
		id,
		&orchestrationClient.GetScanWorkspaceJobForUserParams{Version: "2024-02-16~experimental"})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, http.StatusNotFound, response.StatusCode())
	require.NotNil(t, response.ApplicationvndApiJSON404.Errors)
	doer.AssertExpectations(t)
}

func TestOrchestration_GetScanWorkspaceJobForUserWithResponse_Failure(t *testing.T) {
	doer := &HTTPRequestDoerMock{}
	doer.On("Do", mock.Anything).Return(nil, errors.New("something went wrong")).Run(func(args mock.Arguments) {
		req, ok := args.Get(0).(*http.Request)
		assert.True(t, ok)
		assert.Equal(t, "https://api.snyk.io/rest/orgs/e7ea34c9-de0f-422c-bf2c-4654c2e2da90/scans/b23b92f8-6b3e-4daa-9f15-1083224b25d0?version=2024-02-16~experimental", req.URL.String())
	})
	client, err := orchestrationClient.NewClientWithResponses("https://api.snyk.io/rest", orchestrationClient.WithHTTPClient(doer))
	require.NoError(t, err)

	orgUUID := uuid.MustParse("e7ea34c9-de0f-422c-bf2c-4654c2e2da90")
	id := uuid.MustParse("b23b92f8-6b3e-4daa-9f15-1083224b25d0")
	_, err = client.GetScanWorkspaceJobForUserWithResponse(
		context.Background(),
		orgUUID,
		id,
		&orchestrationClient.GetScanWorkspaceJobForUserParams{Version: "2024-02-16~experimental"})
	require.Error(t, err)
	doer.AssertExpectations(t)
}
