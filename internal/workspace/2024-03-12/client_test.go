package v20240312_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	v20240312 "github.com/snyk/code-client-go/internal/workspace/2024-03-12"
	externalRef3 "github.com/snyk/code-client-go/internal/workspace/2024-03-12/workspaces"
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
	doer.On("Do", mock.Anything).Return(nil, nil).Run(func(args mock.Arguments) {
		req, ok := args.Get(0).(*http.Request)
		assert.True(t, ok)
		assert.Equal(t, "/https//api.snyk.io/rest/orgs/e7ea34c9-de0f-422c-bf2c-4654c2e2da90/workspaces?version=2024-03-12~experimental", req.URL.String())
	})
	client, err := v20240312.NewClientWithResponses("https//api.snyk.io/rest", v20240312.WithHTTPClient(doer))
	require.NoError(t, err)

	orgUUID := uuid.MustParse("e7ea34c9-de0f-422c-bf2c-4654c2e2da90")
	requestId := uuid.New()
	_, err = client.CreateWorkspaceWithApplicationVndAPIPlusJSONBody(context.Background(), orgUUID, &v20240312.CreateWorkspaceParams{
		Version:       "2024-03-12~experimental",
		SnykRequestId: requestId,
	}, v20240312.CreateWorkspaceApplicationVndAPIPlusJSONRequestBody{
		Data: struct {
			Attributes struct {
				BundleId      string                                                       `json:"bundle_id"`
				RepositoryUri string                                                       `json:"repository_uri"`
				WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			} `json:"attributes"`
			Type externalRef3.WorkspacePostRequestDataType `json:"type"`
		}(struct {
			Attributes struct {
				BundleId      string                                                       `json:"bundle_id"`
				RepositoryUri string                                                       `json:"repository_uri"`
				WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			}
			Type externalRef3.WorkspacePostRequestDataType
		}{Attributes: struct {
			BundleId      string                                                       `json:"bundle_id"`
			RepositoryUri string                                                       `json:"repository_uri"`
			WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
		}(struct {
			BundleId      string
			RepositoryUri string
			WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType
		}{BundleId: "bundleId", RepositoryUri: "repositoryUri", WorkspaceType: "workspaceUri"}), Type: "workspace"}),
	})
	require.NoError(t, err)
	doer.AssertExpectations(t)
}

func TestWorkspace_CreateWorkspaceWithApplicationVndAPIPlusJSONBody_Failure(t *testing.T) {
	doer := &HTTPRequestDoerMock{}
	doer.On("Do", mock.Anything).Return(nil, errors.New("something went wrong")).Run(func(args mock.Arguments) {
		req, ok := args.Get(0).(*http.Request)
		assert.True(t, ok)
		assert.Equal(t, "/https//api.snyk.io/rest/orgs/e7ea34c9-de0f-422c-bf2c-4654c2e2da90/workspaces?version=2024-03-12~experimental", req.URL.String())
	})
	client, err := v20240312.NewClientWithResponses("https//api.snyk.io/rest", v20240312.WithHTTPClient(doer))
	require.NoError(t, err)

	orgUUID := uuid.MustParse("e7ea34c9-de0f-422c-bf2c-4654c2e2da90")
	requestId := uuid.New()
	_, err = client.CreateWorkspaceWithApplicationVndAPIPlusJSONBody(context.Background(), orgUUID, &v20240312.CreateWorkspaceParams{
		Version:       "2024-03-12~experimental",
		SnykRequestId: requestId,
	}, v20240312.CreateWorkspaceApplicationVndAPIPlusJSONRequestBody{
		Data: struct {
			Attributes struct {
				BundleId      string                                                       `json:"bundle_id"`
				RepositoryUri string                                                       `json:"repository_uri"`
				WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			} `json:"attributes"`
			Type externalRef3.WorkspacePostRequestDataType `json:"type"`
		}(struct {
			Attributes struct {
				BundleId      string                                                       `json:"bundle_id"`
				RepositoryUri string                                                       `json:"repository_uri"`
				WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
			}
			Type externalRef3.WorkspacePostRequestDataType
		}{Attributes: struct {
			BundleId      string                                                       `json:"bundle_id"`
			RepositoryUri string                                                       `json:"repository_uri"`
			WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType `json:"workspace_type"`
		}(struct {
			BundleId      string
			RepositoryUri string
			WorkspaceType externalRef3.WorkspacePostRequestDataAttributesWorkspaceType
		}{BundleId: "bundleId", RepositoryUri: "repositoryUri", WorkspaceType: "workspaceUri"}), Type: "workspace"}),
	})
	require.Error(t, err)
	doer.AssertExpectations(t)
}
