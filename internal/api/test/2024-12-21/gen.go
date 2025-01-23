//go:build API && !MOCK
// +build API,!MOCK

package v20241221

//go:generate oapi-codegen --config common/common.config.yaml common/common.yaml
//go:generate oapi-codegen --config parameters/orgs.config.yaml parameters/orgs.yaml
//go:generate oapi-codegen --config parameters/tests.config.yaml parameters/tests.yaml
//go:generate oapi-codegen --config models/tests.config.yaml models/tests.yaml
//go:generate oapi-codegen --config spec.config.yaml spec.yaml
