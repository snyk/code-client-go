LOG_PREFIX = --
GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)

TOOLS_BIN := $(shell pwd)/.bin

OVERRIDE_GOCI_LINT_V := v1.55.2
PACT_V := 2.4.2

SHELL:=env PATH=$(TOOLS_BIN)/go:$(TOOLS_BIN)/pact/bin:$(PATH) $(SHELL)

## tools: Install required tooling.
.PHONY: tools
tools: $(TOOLS_BIN)/golangci-lint $(TOOLS_BIN)/go $(TOOLS_BIN)/pact/bin/pact
$(TOOLS_BIN)/golangci-lint:
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(OVERRIDE_GOCI_LINT_V)/install.sh | sh -s -- -b $(TOOLS_BIN)/ $(OVERRIDE_GOCI_LINT_V)

$(TOOLS_BIN)/go:
	mkdir -p ${TOOLS_BIN}/go
	@cat tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -tI % sh -c 'GOBIN=${TOOLS_BIN}/go go install %'

$(TOOLS_BIN)/pact/bin/pact:
	cd $(TOOLS_BIN); curl -fsSL https://raw.githubusercontent.com/pact-foundation/pact-ruby-standalone/v$(PACT_V)/install.sh | PACT_CLI_VERSION=v$(PACT_V) bash

.PHONY: format
format:
	@gofmt -w -l -e .
	@$(TOOLS_BIN)/golangci-lint run --fix -v ./...

.PHONY: lint
lint: $(TOOLS_BIN)/golangci-lint
    ifdef CI
		mkdir -p test/results
		@$(TOOLS_BIN)/golangci-lint run --out-format junit-xml ./... > test/results/lint-tests.xml
    else
		@$(TOOLS_BIN)/golangci-lint run -v ./...
    endif

.PHONY: build
build:
	@echo "Building for $(GOOS)_$(GOARCH)..."
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go build ./...

.PHONY: clean
clean:
	@echo "Cleaning up..."
	@GOOS=$(GOOS) GOARCH=$(GOARCH) go clean -testcache

.PHONY: test
test: 
	@echo "Testing..."
	@go test -cover ./...

.PHONY: testv
testv: 
	@echo "Testing verbosely..."
	@go test -v ./...

.PHONY: generate
generate: $(TOOLS_BIN)/go/mockgen $(TOOLS_BIN)/go/oapi-codegen
	@go generate ./...

.PHONY: download-apis
download-apis: download-workspace-api

WORKSPACE_API_VERSION := 2024-03-12

.PHONY: download-workspace-api
download-workspace-api:
	mkdir -p ./internal/workspace/${WORKSPACE_API_VERSION}
	curl -s https://$(GITHUB_PAT)@raw.githubusercontent.com/snyk/sweater-comb/common-model-v1/components/common.yaml > ./internal/workspace/${WORKSPACE_API_VERSION}/common/common.yaml
	yq -i e '{"components": .}' ./internal/workspace/${WORKSPACE_API_VERSION}/common/common.yaml
	sed -i '' "s@#/schemas/@#/components/schemas/@g" ./internal/workspace/$(WORKSPACE_API_VERSION)/common/common.yaml
	sed -i '' "s@#/headers/@#/components/headers/@g" ./internal/workspace/$(WORKSPACE_API_VERSION)/common/common.yaml

	curl -s https://$(GITHUB_PAT)@raw.githubusercontent.com/snyk/workspace-service/main/src/rest/api/hidden/models/links.yaml > ./internal/workspace/${WORKSPACE_API_VERSION}/links/links.yaml
	yq -i e  '{"components": .}' ./internal/workspace/${WORKSPACE_API_VERSION}/links/links.yaml
	sed -i '' "s@#/schemas@#/components/schemas@g" ./internal/workspace/$(WORKSPACE_API_VERSION)/links/links.yaml

	curl -s https://$(GITHUB_PAT)@raw.githubusercontent.com/snyk/workspace-service/main/src/rest/api/hidden/parameters/orgs.yaml > ./internal/workspace/$(WORKSPACE_API_VERSION)/parameters/orgs.yaml
	yq -i e  '{"components": {"parameters": .}}' ./internal/workspace/${WORKSPACE_API_VERSION}/parameters/orgs.yaml

	curl -s https://$(GITHUB_PAT)@raw.githubusercontent.com/snyk/workspace-service/main/src/rest/api/hidden/parameters/request-id.yaml > ./internal/workspace/$(WORKSPACE_API_VERSION)/parameters/request-id.yaml
	yq -i e  '{"components": {"parameters": .}}' ./internal/workspace/${WORKSPACE_API_VERSION}/parameters/request-id.yaml

	curl -s https://$(GITHUB_PAT)@raw.githubusercontent.com/snyk/workspace-service/main/src/rest/api/hidden/parameters/user-agent.yaml > ./internal/workspace/$(WORKSPACE_API_VERSION)/parameters/user-agent.yaml
	yq -i e  '{"components": {"parameters": .}}' ./internal/workspace/${WORKSPACE_API_VERSION}/parameters/user-agent.yaml

	curl -s https://$(GITHUB_PAT)@raw.githubusercontent.com/snyk/workspace-service/main/src/rest/api/hidden/resources/workspaces/$(WORKSPACE_API_VERSION)/models/workspaces.yaml > ./internal/workspace/${WORKSPACE_API_VERSION}/workspaces/workspaces.yaml
	yq -i e  '{"components": .}' ./internal/workspace/${WORKSPACE_API_VERSION}/workspaces/workspaces.yaml
	sed -i '' "s@https://raw.githubusercontent.com/snyk/sweater-comb/common-model-v1/components/common.yaml#@../common/common.yaml#/components@g" ./internal/workspace/$(WORKSPACE_API_VERSION)/workspaces/workspaces.yaml
	sed -i '' "s@../../../../models/links.yaml#@../links/links.yaml#/components@g" ./internal/workspace/$(WORKSPACE_API_VERSION)/workspaces/workspaces.yaml

	curl -s https://$(GITHUB_PAT)@raw.githubusercontent.com/snyk/workspace-service/main/src/rest/api/hidden/resources/workspaces/$(WORKSPACE_API_VERSION)/spec.yaml > ./internal/workspace/${WORKSPACE_API_VERSION}/spec.yaml
	sed -i '' "s@./models/workspaces.yaml#/schemas@./workspaces/workspaces.yaml#/components/schemas@g" ./internal/workspace/$(WORKSPACE_API_VERSION)/spec.yaml
	sed -i '' "s@#/components/x-snyk-common@./common/common.yaml#/components@g" ./internal/workspace/$(WORKSPACE_API_VERSION)/spec.yaml
	sed -i '' "s@../../../parameters/orgs.yaml#@./parameters/orgs.yaml#/components/parameters@g" ./internal/workspace/$(WORKSPACE_API_VERSION)/spec.yaml
	sed -i '' "s@../../../parameters/request-id.yaml#@./parameters/request-id.yaml#/components/parameters@g" ./internal/workspace/$(WORKSPACE_API_VERSION)/spec.yaml
	sed -i '' "s@../../../parameters/user-agent.yaml#@./parameters/user-agent.yaml#/components/parameters@g" ./internal/workspace/$(WORKSPACE_API_VERSION)/spec.yaml

.PHONY: help
help:
	@echo "Main targets:"
	@echo "$(LOG_PREFIX) format"
	@echo "$(LOG_PREFIX) lint"
	@echo "$(LOG_PREFIX) build"
	@echo "$(LOG_PREFIX) test"
	@echo "$(LOG_PREFIX) testv                      Test versbosely"
	@echo "$(LOG_PREFIX) GOOS                       Specify Operating System to compile for (see golang GOOS, default=$(GOOS))"
	@echo "$(LOG_PREFIX) GOARCH                     Specify Architecture to compile for (see golang GOARCH, default=$(GOARCH))"
