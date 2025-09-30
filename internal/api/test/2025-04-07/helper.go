package v20250407

import (
	openapi_types "github.com/oapi-codegen/runtime/types"

	externalRef0 "github.com/snyk/code-client-go/internal/api/test/2025-04-07/common"
	v20250407 "github.com/snyk/code-client-go/internal/api/test/2025-04-07/models"
)

const ApiVersion = "2025-04-07"
const DocumentApiVersion = "2025-04-07"

type CreateTestOption func(*CreateTestApplicationVndAPIPlusJSONRequestBody)

func WithInputBundle(id string, localFilePath string, repoUrl *string, limitTestToFiles []string, commitId *string) CreateTestOption {
	return func(body *CreateTestApplicationVndAPIPlusJSONRequestBody) {
		bundleInput := v20250407.TestInputSourceBundle{
			BundleId: id,
			Type:     v20250407.SourceBundle,
			Metadata: struct {
				CommitId         *string   `json:"commit_id,omitempty"`
				LimitTestToFiles *[]string `json:"limit_test_to_files,omitempty"`
				LocalFilePath    string    `json:"local_file_path"`
				RepoUrl          *string   `json:"repo_url,omitempty"`
			}{LocalFilePath: localFilePath, RepoUrl: repoUrl, CommitId: commitId},
		}

		if len(limitTestToFiles) > 0 {
			bundleInput.Metadata.LimitTestToFiles = &limitTestToFiles
		}

		body.Data.Attributes.Input.FromTestInputSourceBundle(bundleInput)
	}
}

func WithInputLegacyScmProject(project v20250407.TestInputLegacyScmProject) CreateTestOption {
	return func(body *CreateTestApplicationVndAPIPlusJSONRequestBody) {
		body.Data.Attributes.Input.FromTestInputLegacyScmProject(project)
	}
}

func WithScanType(t v20250407.ResultType) CreateTestOption {
	return func(body *CreateTestApplicationVndAPIPlusJSONRequestBody) {
		body.Data.Attributes.Configuration.Scan = &v20250407.ScanConfig{
			ResultType: &t,
		}
	}
}

func ensureOutput(body *CreateTestApplicationVndAPIPlusJSONRequestBody) *v20250407.OutputConfig {
	if body.Data.Attributes.Configuration.Output == nil {
		body.Data.Attributes.Configuration.Output = &v20250407.OutputConfig{}
	}
	return body.Data.Attributes.Configuration.Output
}

func WithProjectName(name *string) CreateTestOption {
	return func(body *CreateTestApplicationVndAPIPlusJSONRequestBody) {
		if name == nil {
			return
		}
		out := ensureOutput(body)
		out.ProjectName = name
	}
}

func WithProjectId(id openapi_types.UUID) CreateTestOption {
	return func(body *CreateTestApplicationVndAPIPlusJSONRequestBody) {
		out := ensureOutput(body)
		out.ProjectId = &id
	}
}

func WithTargetName(name *string) CreateTestOption {
	return func(body *CreateTestApplicationVndAPIPlusJSONRequestBody) {
		if name == nil || len(*name) == 0 {
			return
		}
		out := ensureOutput(body)
		out.TargetName = name
	}
}

func WithTargetReference(targetRef *string) CreateTestOption {
	return func(body *CreateTestApplicationVndAPIPlusJSONRequestBody) {
		if targetRef == nil || len(*targetRef) == 0 {
			return
		}
		out := ensureOutput(body)
		out.TargetReference = targetRef
	}
}

func WithReporting(report *bool) CreateTestOption {
	return func(body *CreateTestApplicationVndAPIPlusJSONRequestBody) {
		if report == nil {
			return
		}
		out := ensureOutput(body)
		out.Report = report
	}
}

func NewCreateTestApplicationBody(options ...CreateTestOption) *CreateTestApplicationVndAPIPlusJSONRequestBody {
	result := &CreateTestApplicationVndAPIPlusJSONRequestBody{}
	result.Data.Type = v20250407.CreateTestRequestBodyDataTypeTest
	result.Data.Attributes.Input = &v20250407.TestAttributes_Input{}
	result.Data.Attributes.Configuration = &v20250407.TestConfiguration{}

	for _, option := range options {
		option(result)
	}

	return result
}

func NewTestInputLegacyScmProject(projectId openapi_types.UUID, commitId string) v20250407.TestInputLegacyScmProject {
	return v20250407.TestInputLegacyScmProject{
		ProjectId: projectId,
		CommitId:  commitId,
		Type:      v20250407.LegacyScmProject,
	}
}

func NewTestResponse() *v20250407.TestResult {
	return &v20250407.TestResult{
		Data: struct {
			Attributes v20250407.TestState          `json:"attributes"`
			Id         openapi_types.UUID           `json:"id"`
			Type       v20250407.TestResultDataType `json:"type"`
		}{},
	}
}

func NewGetComponentsState() *v20250407.GetComponentsResponse {
	return &v20250407.GetComponentsResponse{
		Data: []v20250407.GetComponentsResponseItem{
			{
				Attributes: v20250407.ComponentAttributes{},
				Id:         "1",
				Type:       v20250407.Component,
			},
		},
		Jsonapi: externalRef0.JsonApi{
			Version: ApiVersion,
		},
		Links: struct {
			Next *externalRef0.LinkProperty `json:"next,omitempty"`
			Prev *externalRef0.LinkProperty `json:"prev,omitempty"`
			Self *externalRef0.LinkProperty `json:"self,omitempty"`
		}{},
	}
}
