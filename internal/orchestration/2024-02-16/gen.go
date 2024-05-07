//go:build API && !MOCK
// +build API,!MOCK

package v20240216

//go:generate oapi-codegen --config common/common.config.yaml common/common.yaml
//go:generate oapi-codegen --config parameters/orgs.config.yaml parameters/orgs.yaml
//go:generate oapi-codegen --config parameters/scans.config.yaml parameters/scans.yaml
//go:generate oapi-codegen --config scans/scans.config.yaml scans/scans.yaml
//go:generate oapi-codegen --config spec.config.yaml spec.yaml
