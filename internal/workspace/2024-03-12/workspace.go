package v20240312

import (
	"context"
	"io"

	externalRef2 "github.com/snyk/code-client-go/internal/workspace/2024-03-12/parameters"
)

//go:generate mockgen -destination=mocks/workspace.go -source=workspace.go -package mocks
type Workspace interface {
	CreateWorkspaceWithBodyWithResponse(ctx context.Context, orgId externalRef2.OrgId, params *CreateWorkspaceParams, contentType string, body io.Reader, reqEditors ...RequestEditorFn) (*CreateWorkspaceResponse, error)
	CreateWorkspaceWithApplicationVndAPIPlusJSONBodyWithResponse(ctx context.Context, orgId externalRef2.OrgId, params *CreateWorkspaceParams, body CreateWorkspaceApplicationVndAPIPlusJSONRequestBody, reqEditors ...RequestEditorFn) (*CreateWorkspaceResponse, error)
}
