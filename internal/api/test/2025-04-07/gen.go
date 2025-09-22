//go:build API && !MOCK
// +build API,!MOCK

package v20250407

//go:generate go tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config common/common.config.yaml common/common.yaml
//go:generate go tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config parameters/orgs.config.yaml parameters/orgs.yaml
//go:generate go tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config parameters/tests.config.yaml parameters/tests.yaml
//go:generate go tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config models/tests.config.yaml models/tests.yaml
//go:generate go tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config spec.config.yaml spec.yaml
//go:generate go tool github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen --config models/components.config.yaml models/components.yaml
