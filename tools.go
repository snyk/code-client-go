//go:build tools

package codeClient

import (
	_ "github.com/golang/mock/mockgen"
	_ "github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen"
	_ "github.com/pact-foundation/pact-go/v2"
)
