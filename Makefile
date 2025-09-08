LOG_PREFIX = --
GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)

TOOLS_BIN := $(shell pwd)/.bin

OVERRIDE_GOCI_LINT_V := v1.64.8
GOCI_LINT_TARGETS := $(TOOLS_BIN)/golangci-lint $(TOOLS_BIN)/.golangci-lint_$(OVERRIDE_GOCI_LINT_V)

PACT_CLI_V := v2.4.4
PACT_CLI_TARGETS := $(TOOLS_BIN)/pact/bin/pact-broker $(TOOLS_BIN)/.pact_$(PACT_CLI_V)
PACT_GO_V := v2.4.1
PACT_GO_LIB_TARGETS := /tmp/.libpact-ffi_$(PACT_GO_V) # Only use a marker file since lib extension is either .so or .dll

SHELL:=env PATH=$(TOOLS_BIN)/go:$(TOOLS_BIN)/pact/bin:$(PATH) $(SHELL)

## tools: Install required tooling.
.PHONY: tools
tools: $(TOOLS_BIN)/go $(GOCI_LINT_TARGETS) $(PACT_CLI_TARGETS) $(PACT_GO_LIB_TARGETS)

$(TOOLS_BIN):
	@mkdir -p $(TOOLS_BIN)

$(GOCI_LINT_TARGETS): $(TOOLS_BIN)
	@rm -f $(TOOLS_BIN)/.golangci-lint_*
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(OVERRIDE_GOCI_LINT_V)/install.sh | sh -s -- -b $(TOOLS_BIN) $(OVERRIDE_GOCI_LINT_V)
	@touch $(TOOLS_BIN)/.golangci-lint_$(OVERRIDE_GOCI_LINT_V)

$(PACT_CLI_TARGETS): $(TOOLS_BIN)
	@rm -f $(TOOLS_BIN)/.pact_*
	@cd $(TOOLS_BIN); curl -fsSL https://raw.githubusercontent.com/pact-foundation/pact-ruby-standalone/master/install.sh | PACT_CLI_VERSION=$(PACT_CLI_V) bash; cd ../
	@touch $(TOOLS_BIN)/.pact_$(PACT_CLI_V)

$(TOOLS_BIN)/go:
	mkdir -p ${TOOLS_BIN}/go
	@cat tools.go | grep _ | awk -F'"' '{print $$2}' | xargs -tI % sh -c 'GOBIN=${TOOLS_BIN}/go go install %'

$(PACT_GO_LIB_TARGETS): $(TOOLS_BIN)/go
	@rm -f /tmp/.libpact-ffi_*
	@GOBIN=${TOOLS_BIN}/go ${TOOLS_BIN}/go/pact-go -l DEBUG install -d /tmp
	@touch /tmp/.libpact-ffi_$(PACT_GO_V)

.PHONY: format
format: $(GOCI_LINT_TARGETS)
	@gofmt -w -l -e .
	@$(TOOLS_BIN)/golangci-lint run --fix ./...

.PHONY: lint
lint: $(GOCI_LINT_TARGETS)
    ifdef CI
		mkdir -p test/results
		@$(TOOLS_BIN)/golangci-lint run --out-format junit-xml ./... > test/results/lint-tests.xml
    else
		@$(TOOLS_BIN)/golangci-lint run ./...
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
	@rm -f /tmp/.libpact-ffi_*
	@rm -f /tmp/libpact_ffi.*

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
contract-test: $(PACT_GO_LIB_TARGETS)
	@echo "Contract testing..."
	@go test -tags=contract ./...

.PHONY: publish-contract
publish-contract: $(PACT_CLI_TARGETS)
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
download-apis: download-test-api

.PHONY: download-workspace-api
download-workspace-api:
	./scripts/download-workspace-api.py

.PHONY: download-orchestration-api
download-orchestration-api:
	./scripts/download-orchestration-api.py

.PHONY: download-test-api
download-test-api:
	./scripts/download-test-api.py

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
