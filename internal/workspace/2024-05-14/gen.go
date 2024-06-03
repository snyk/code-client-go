//go:build API && !MOCK
// +build API,!MOCK

package v20240514

//go:generate oapi-codegen --config common/common.config.yaml common/common.yaml
//go:generate oapi-codegen --config parameters/orgs.config.yaml parameters/orgs.yaml
//go:generate oapi-codegen --config parameters/request-id.config.yaml parameters/request-id.yaml
//go:generate oapi-codegen --config parameters/content-type.config.yaml parameters/content-type.yaml
//go:generate oapi-codegen --config parameters/user-agent.config.yaml parameters/user-agent.yaml
//go:generate oapi-codegen --config workspaces/workspaces.config.yaml workspaces/workspaces.yaml
//go:generate oapi-codegen --config links/links.config.yaml links/links.yaml
//go:generate oapi-codegen --config spec.config.yaml spec.yaml
