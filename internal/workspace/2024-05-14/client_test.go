package v20240514_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	workspaceClient "github.com/snyk/code-client-go/internal/workspace/2024-05-14"
	externalRef3 "github.com/snyk/code-client-go/internal/workspace/2024-05-14/workspaces"
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

func TestWorkspace_CreateWorkspaceWithApplicationVndAPIPlusJSONBody_Success(t *testing.T) {
	doer := &HTTPRequestDoerMock{}
	mockResponse := http.Response{
		Body: io.NopCloser(bytes.NewBufferString(`{
  "data": {
    "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "type": "cli"
  },
  "jsonapi": {
    "version": "1.0"
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
		assert.Equal(t, "https://api.snyk.io/rest/orgs/e7ea34c9-de0f-422c-bf2c-4654c2e2da90/workspaces?version=2024-05-14~experimental", req.URL.String())
	})
	client, err := workspaceClient.NewClientWithResponses("https://api.snyk.io/rest", workspaceClient.WithHTTPClient(doer))
	require.NoError(t, err)

	orgUUID := uuid.MustParse("e7ea34c9-de0f-422c-bf2c-4654c2e2da90")
	requestId := uuid.New()
	response, err := client.CreateWorkspaceWithApplicationVndAPIPlusJSONBodyWithResponse(context.Background(), orgUUID, &workspaceClient.CreateWorkspaceParams{
		Version:       "2024-05-14~experimental",
		SnykRequestId: requestId,
	}, workspaceClient.CreateWorkspaceApplicationVndAPIPlusJSONRequestBody{
		Data: struct {
			Attributes struct {
				BundleId      string                                                       `json:"bundle_id"`
				RepositoryUri string                                                       `json:"repository_uri"`
				RootFolderId  string                                                       `json:"root_folder_id"`
				WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			} `json:"attributes"`
			Type externalRef3.WorkspacePostRequestDataType `json:"type"`
		}(struct {
			Attributes struct {
				BundleId      string                                                       `json:"bundle_id"`
				RepositoryUri string                                                       `json:"repository_uri"`
				RootFolderId  string                                                       `json:"root_folder_id"`
				WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			}
			Type externalRef3.WorkspacePostRequestDataType
		}{Attributes: struct {
			BundleId      string                                                       `json:"bundle_id"`
			RepositoryUri string                                                       `json:"repository_uri"`
			RootFolderId  string                                                       `json:"root_folder_id"`
			WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
		}(struct {
			BundleId      string
			RepositoryUri string
			RootFolderId  string
			WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType
		}{BundleId: "bundleId", RepositoryUri: "repositoryUri", WorkspaceType: "workspaceUri"}), Type: "workspace"}),
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, 201, response.StatusCode())
	require.Equal(t, "3fa85f64-5717-4562-b3fc-2c963f66afa6", response.ApplicationvndApiJSON201.Data.Id.String())
	doer.AssertExpectations(t)
}

func TestWorkspace_CreateWorkspaceWithApplicationVndAPIPlusJSONBody_Invalid(t *testing.T) {
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
		StatusCode: http.StatusBadRequest,
	}
	doer.On("Do", mock.Anything).Return(&mockResponse, nil).Run(func(args mock.Arguments) {
		req, ok := args.Get(0).(*http.Request)
		assert.True(t, ok)
		assert.Equal(t, "https://api.snyk.io/rest/orgs/e7ea34c9-de0f-422c-bf2c-4654c2e2da90/workspaces?version=2024-05-14~experimental", req.URL.String())
	})
	client, err := workspaceClient.NewClientWithResponses("https://api.snyk.io/rest", workspaceClient.WithHTTPClient(doer))
	require.NoError(t, err)

	orgUUID := uuid.MustParse("e7ea34c9-de0f-422c-bf2c-4654c2e2da90")
	requestId := uuid.New()
	response, err := client.CreateWorkspaceWithApplicationVndAPIPlusJSONBodyWithResponse(context.Background(), orgUUID, &workspaceClient.CreateWorkspaceParams{
		Version:       "2024-05-14~experimental",
		SnykRequestId: requestId,
	}, workspaceClient.CreateWorkspaceApplicationVndAPIPlusJSONRequestBody{
		Data: struct {
			Attributes struct {
				BundleId      string                                                       `json:"bundle_id"`
				RepositoryUri string                                                       `json:"repository_uri"`
				RootFolderId  string                                                       `json:"root_folder_id"`
				WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			} `json:"attributes"`
			Type externalRef3.WorkspacePostRequestDataType `json:"type"`
		}(struct {
			Attributes struct {
				BundleId      string                                                       `json:"bundle_id"`
				RepositoryUri string                                                       `json:"repository_uri"`
				RootFolderId  string                                                       `json:"root_folder_id"`
				WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			}
			Type externalRef3.WorkspacePostRequestDataType
		}{Attributes: struct {
			BundleId      string                                                       `json:"bundle_id"`
			RepositoryUri string                                                       `json:"repository_uri"`
			RootFolderId  string                                                       `json:"root_folder_id"`
			WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
		}(struct {
			BundleId      string
			RepositoryUri string
			RootFolderId  string
			WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType
		}{BundleId: "bundleId", RepositoryUri: "repositoryUri", WorkspaceType: "workspaceUri"}), Type: "workspace"}),
	})
	require.NoError(t, err)
	require.NotNil(t, response)
	require.Equal(t, http.StatusBadRequest, response.StatusCode())
	require.NotNil(t, response.ApplicationvndApiJSON400.Errors)
	doer.AssertExpectations(t)
}

func TestWorkspace_CreateWorkspaceWithApplicationVndAPIPlusJSONBody_Failure(t *testing.T) {
	doer := &HTTPRequestDoerMock{}
	doer.On("Do", mock.Anything).Return(nil, errors.New("something went wrong")).Run(func(args mock.Arguments) {
		req, ok := args.Get(0).(*http.Request)
		assert.True(t, ok)
		assert.Equal(t, "https://api.snyk.io/rest/orgs/e7ea34c9-de0f-422c-bf2c-4654c2e2da90/workspaces?version=2024-05-14~experimental", req.URL.String())
	})
	client, err := workspaceClient.NewClientWithResponses("https://api.snyk.io/rest", workspaceClient.WithHTTPClient(doer))
	require.NoError(t, err)

	orgUUID := uuid.MustParse("e7ea34c9-de0f-422c-bf2c-4654c2e2da90")
	requestId := uuid.New()
	_, err = client.CreateWorkspaceWithApplicationVndAPIPlusJSONBodyWithResponse(context.Background(), orgUUID, &workspaceClient.CreateWorkspaceParams{
		Version:       "2024-05-14~experimental",
		SnykRequestId: requestId,
	}, workspaceClient.CreateWorkspaceApplicationVndAPIPlusJSONRequestBody{
		Data: struct {
			Attributes struct {
				BundleId      string                                                       `json:"bundle_id"`
				RepositoryUri string                                                       `json:"repository_uri"`
				RootFolderId  string                                                       `json:"root_folder_id"`
				WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			} `json:"attributes"`
			Type externalRef3.WorkspacePostRequestDataType `json:"type"`
		}(struct {
			Attributes struct {
				BundleId      string                                                       `json:"bundle_id"`
				RepositoryUri string                                                       `json:"repository_uri"`
				RootFolderId  string                                                       `json:"root_folder_id"`
				WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			}
			Type externalRef3.WorkspacePostRequestDataType
		}{Attributes: struct {
			BundleId      string                                                       `json:"bundle_id"`
			RepositoryUri string                                                       `json:"repository_uri"`
			RootFolderId  string                                                       `json:"root_folder_id"`
			WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
		}(struct {
			BundleId      string
			RepositoryUri string
			RootFolderId  string
			WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType
		}{BundleId: "bundleId", RepositoryUri: "repositoryUri", WorkspaceType: "workspaceUri"}), Type: "workspace"}),
	})
	require.Error(t, err)
	doer.AssertExpectations(t)
}
