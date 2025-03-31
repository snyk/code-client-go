package v20241221

import (
	openapi_types "github.com/oapi-codegen/runtime/types"

	v20241221 "github.com/snyk/code-client-go/v2/internal/api/test/2024-12-21/models"
)

const ApiVersion = "2024-12-21"
const DocumentApiVersion = "2024-10-15~experimental"

type CreateTestOption func(*CreateTestApplicationVndAPIPlusJSONRequestBody)

func WithInputBundle(id string, localFilePath string, repoUrl *string, limitTestToFiles []string) CreateTestOption {
	return func(body *CreateTestApplicationVndAPIPlusJSONRequestBody) {
		bundleInput := v20241221.TestInputBundle{
			BundleId: id,
			Type:     v20241221.Bundle,
			Metadata: struct {
				LimitTestToFiles *[]string `json:"limit_test_to_files,omitempty"`
				LocalFilePath    string    `json:"local_file_path"`
				RepoUrl          *string   `json:"repo_url,omitempty"`
			}{LocalFilePath: localFilePath, RepoUrl: repoUrl},
		}

		if len(limitTestToFiles) > 0 {
			bundleInput.Metadata.LimitTestToFiles = &limitTestToFiles
		}

		body.Data.Attributes.Input.FromTestInputBundle(bundleInput)
	}
}

func WithInputLegacyScmProject(project v20241221.TestInputLegacyScmProject) CreateTestOption {
	return func(body *CreateTestApplicationVndAPIPlusJSONRequestBody) {
		body.Data.Attributes.Input.FromTestInputLegacyScmProject(project)
	}
}

func WithScanType(t v20241221.Scan) CreateTestOption {
	return func(body *CreateTestApplicationVndAPIPlusJSONRequestBody) {
		body.Data.Attributes.Configuration.Scan = struct {
			ResultType *v20241221.Scan `json:"result_type,omitempty"`
		}{ResultType: &t}
	}
}

func ensureOutput(body *CreateTestApplicationVndAPIPlusJSONRequestBody) *struct {
	Label           *string             `json:"label,omitempty"`
	ProjectId       *openapi_types.UUID `json:"project_id,omitempty"`
	ProjectName     *string             `json:"project_name,omitempty"`
	Report          *bool               `json:"report,omitempty"`
	TargetName      *string             `json:"target_name,omitempty"`
	TargetReference *string             `json:"target_reference,omitempty"`
} {
	if body.Data.Attributes.Configuration.Output == nil {
		body.Data.Attributes.Configuration.Output = &struct {
			Label           *string             `json:"label,omitempty"`
			ProjectId       *openapi_types.UUID `json:"project_id,omitempty"`
			ProjectName     *string             `json:"project_name,omitempty"`
			Report          *bool               `json:"report,omitempty"`
			TargetName      *string             `json:"target_name,omitempty"`
			TargetReference *string             `json:"target_reference,omitempty"`
		}{}
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
	result.Data.Type = v20241221.CreateTestRequestBodyDataTypeTest

	for _, option := range options {
		option(result)
	}

	return result
}

func NewTestInputLegacyScmProject(projectId openapi_types.UUID, commitId string) v20241221.TestInputLegacyScmProject {
	return v20241221.TestInputLegacyScmProject{
		ProjectId: projectId,
		CommitId:  commitId,
		Type:      v20241221.LegacyScmProject,
	}
}

func NewTestResponse() *v20241221.TestResult {
	return &v20241221.TestResult{
		Data: struct {
			Attributes v20241221.TestState          `json:"attributes"`
			Id         openapi_types.UUID           `json:"id"`
			Type       v20241221.TestResultDataType `json:"type"`
		}{},
	}
}

func NewTestCompleteState() *v20241221.TestCompletedState {
	return &v20241221.TestCompletedState{
		Status: v20241221.TestCompletedStateStatusCompleted,
		Documents: struct {
			EnrichedSarif string `json:"enriched_sarif"`
		}{},
		Results: struct {
			Outcome struct {
				Result v20241221.TestCompletedStateResultsOutcomeResult `json:"result"`
			} `json:"outcome"`
			Webui *struct {
				Link       *string             `json:"link,omitempty"`
				ProjectId  *openapi_types.UUID `json:"project_id,omitempty"`
				SnapshotId *openapi_types.UUID `json:"snapshot_id,omitempty"`
			} `json:"webui,omitempty"`
		}{
			Webui: &struct {
				Link       *string             `json:"link,omitempty"`
				ProjectId  *openapi_types.UUID `json:"project_id,omitempty"`
				SnapshotId *openapi_types.UUID `json:"snapshot_id,omitempty"`
			}{},
		},
	}
}
