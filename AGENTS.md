# Agent Instructions for code-client-go

## Before Committing (pre-commit)

Run these checks before every commit. They mirror what CI does in the "Lint & Format" job.

1. **Format**: `gofmt -w -l -e .`
2. **Lint with autofix**: `.bin/golangci-lint run --fix ./...` (or `make format` which does both)
3. **Regenerate mocks**: `go generate -tags MOCK ./...`
4. **Tidy modules**: `go mod tidy`
5. **Verify no drift**: `git diff --name-only` should be empty. If any files changed from steps 1-4, stage them before committing.

The combined shortcut: `make format && make generate && go mod tidy`

## Before Pushing (pre-push)

1. **Build**: `go build ./...`
2. **Unit tests**: `go test -cover ./...`

## Setup

Install the repo's git hooks so these checks run automatically:

```
make tools   # install golangci-lint and other tooling
make hooks   # point git to .githooks/
```

## Key CI Checks

The CircleCI "Lint & Format" job runs `make format`, `make generate`, `go mod tidy`, then verifies `git status --porcelain` produces zero lines of output. Any uncommitted formatting, lint fixes, or generated code changes will fail CI.

## Code Style

- This is a Go project using `gofmt` for formatting and `golangci-lint` (v1.64.8) for linting.
- Mocks are generated with `go:generate` tags. After changing any interface in `config/config.go` or other mock-sourced files, run `make generate` and commit the results.
- Tests use `testify/assert` and `gomock`.
