LOG_PREFIX = --
GOOS = $(shell go env GOOS)
GOARCH = $(shell go env GOARCH)

TOOLS_BIN := $(shell pwd)/.bin

OVERRIDE_GOCI_LINT_V := v1.55.2

## tools: Install required tooling.
.PHONY: tools
tools: $(TOOLS_BIN)/golangci-lint

$(TOOLS_BIN)/golangci-lint:
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/$(OVERRIDE_GOCI_LINT_V)/install.sh | sh -s -- -b $(TOOLS_BIN)/ $(OVERRIDE_GOCI_LINT_V)

.PHONY: format
format:
	@gofmt -w -l -e .

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
generate: 
	@go generate ./...

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