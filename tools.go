//go:build tools

package codeClient

import (
	_ "github.com/deepmap/oapi-codegen/cmd/oapi-codegen"
	_ "github.com/golang/mock/mockgen"
	_ "github.com/pact-foundation/pact-go/v2"
)
