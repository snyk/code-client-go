package v20241221

import (
	v20241221 "github.com/snyk/code-client-go/internal/api/test/2024-12-21/models"
)

type CreateTestOption func(*CreateTestApplicationVndAPIPlusJSONRequestBody)

func WithInputBundle(id string, localFilePath string, repoUrl *string) CreateTestOption {
	return func(body *CreateTestApplicationVndAPIPlusJSONRequestBody) {
		bundleInput := v20241221.TestInputBundle{
			BundleId: id,
			Type:     v20241221.Bundle,
			Metadata: struct {
				LocalFilePath string  `json:"local_file_path"`
				RepoUrl       *string `json:"repo_url,omitempty"`
			}{LocalFilePath: localFilePath, RepoUrl: repoUrl},
		}

		body.Data.Attributes.Input.FromTestInputBundle(bundleInput)
	}
}

func NewCreateTestApplicationBody(options ...CreateTestOption) *CreateTestApplicationVndAPIPlusJSONRequestBody {
	result := &CreateTestApplicationVndAPIPlusJSONRequestBody{}

	for _, option := range options {
		option(result)
	}

	return result
}
