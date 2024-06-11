LOG_PREFIX = --
GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)

TOOLS_BIN := $(shell pwd)/.bin

OVERRIDE_GOCI_LINT_V := v1.55.2
SHELL:=env PATH=$(TOOLS_BIN)/go:$(TOOLS_BIN)/pact/bin:$(PATH) $(SHELL)

## tools: Install required tooling.
.PHONY: tools
tools: $(TOOLS_BIN)/golangci-lint $(TOOLS_BIN)/go
$(TOOLS_BIN)/golangci-lint:
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(OVERRIDE_GOCI_LINT_V)/install.sh | sh -s -- -b $(TOOLS_BIN)/ $(OVERRIDE_GOCI_LINT_V)

$(TOOLS_BIN)/pact-broker:
	@cd $(TOOLS_BIN); curl -fsSL https://raw.githubusercontent.com/pact-foundation/pact-ruby-standalone/master/install.sh | PACT_CLI_VERSION=v2.4.4 bash; cd ../

$(TOOLS_BIN)/go:
	mkdir -p ${TOOLS_BIN}/go
	@cat tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -tI % sh -c 'GOBIN=${TOOLS_BIN}/go go install %'
	@GOBIN=${TOOLS_BIN}/go ${TOOLS_BIN}/go/pact-go -l DEBUG install -d /tmp

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
	@rm -rf $(TOOLS_BIN)

.PHONY: test
test:
	@echo "Testing..."
	@go test -cover . ./...

.PHONY: testv
testv:
	@echo "Testing verbosely..."
	@go test -v . ./...

.PHONY: smoke-test
smoke-test:
	@echo "Smoke testing..."
	@go test -tags=smoke

.PHONY: contract-test
contract-test: $(TOOLS_BIN)
	@echo "Contract testing..."
	@go test -tags=contract ./...

.PHONY: publish-contract
publish-contract: $(TOOLS_BIN)/pact-broker
	./scripts/publish-contract.sh

.PHONY: generate
generate:
    ifdef CI
		$(MAKE) generate-mocks
    else
		$(MAKE) generate-mocks
		$(MAKE) generate-apis
    endif

.PHONY: generate-mocks
generate-mocks: $(TOOLS_BIN)/go/mockgen
	@go generate -tags MOCK ./...

.PHONY: generate-apis
generate-apis: $(TOOLS_BIN)/go/oapi-codegen download-apis
	@go generate -tags API,!MOCK ./...

.PHONY: download-apis
download-apis: download-workspace-api download-orchestration-api

.PHONY: download-workspace-api
download-workspace-api:
	./scripts/download-workspace-api.py

.PHONY: download-orchestration-api
download-orchestration-api:
	./scripts/download-orchestration-api.py

.PHONY: help
help:
	@echo "Main targets:"
	@echo "$(LOG_PREFIX) format"
	@echo "$(LOG_PREFIX) lint"
	@echo "$(LOG_PREFIX) build"
	@echo "$(LOG_PREFIX) test"
	@echo "$(LOG_PREFIX) testv                      Test verbosely"
	@echo "$(LOG_PREFIX) smoke-test"
	@echo "$(LOG_PREFIX) generate"
	@echo "$(LOG_PREFIX) generate-mocks"
	@echo "$(LOG_PREFIX) generate-apis"
	@echo "$(LOG_PREFIX) download-apis"
	@echo "$(LOG_PREFIX) download-workspace-api"
	@echo "$(LOG_PREFIX) download-orchestration-api"
	@echo "$(LOG_PREFIX) contract-test
	@echo "$(LOG_PREFIX) smoke-test
	@echo "$(LOG_PREFIX) publish-contract
	@echo "$(LOG_PREFIX) GOOS                       Specify Operating System to compile for (see golang GOOS, default=$(GOOS))"
	@echo "$(LOG_PREFIX) GOARCH                     Specify Architecture to compile for (see golang GOARCH, default=$(GOARCH))"
