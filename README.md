# code-client-go

A library that exposes scanning capabilities for Snyk Code that can be used in the [Snyk CLI](https://github.com/snyk/cli) as well as Snyk IDE plugins using the [Snyk Language Server](https://github.com/snyk/snyk-ls).

## Installation

```shell script
$ go get github.com/snyk/code-client-go
```

## Usage

### Extension Entry Point

The primary way to integrate Snyk Code scanning into the Snyk CLI and IDE is through the workflows from the [go-application-framework](https://github.com/snyk/go-application-framework/blob/main/CONTRIBUTING.md). The `Init` function registers the `code.test` workflow with the engine, which uses `codeWorkflowEntryPoint` as its entry point.

```go
import (
    "github.com/snyk/code-client-go/pkg/code"
    "github.com/snyk/go-application-framework/pkg/workflow"
)

// Register the code workflow with the engine
err := code.Init(engine)

...

// The workflow can then be invoked via WORKFLOWID_CODE
engine.Invoke(code.WORKFLOWID_CODE)
```

The `codeWorkflowEntryPoint` function:
- Checks if SAST is enabled for the organization
- Determines whether to use the native or legacy implementation based on feature flags
- Routes to either `EntryPointNative` (for Code Consistent Ignores support) or `EntryPointLegacy`
- Returns workflow data containing scan results as local findings

### Library Functions

For more granular control and a custom implementation, the following library components can be used directly:

#### HTTP Client

Use the HTTP client to make HTTP requests with configured retriable codes and authorisation headers for Snyk Rest APIs.

```go
import (
    "net/http"

    "github.com/rs/zerolog"
    codeClientHTTP "github.com/snyk/code-client-go/http"
    codeClientObservability  "github.com/snyk/code-client-go/observability"
)

logger := zerlog.NewLogger(...)
instrumentor := codeClientObservability.NewInstrumentor()
errorReporter := codeClientObservability.NewErrorReporter()
httpClient := codeClientHTTP.NewHTTPClient(
    func() *http.Client {
        return &http.Client{
            Timeout: time.Duration(1) * time.Second,
        }
    },
    codeClientHTTP.WithRetryCount(1),
    codeClientHTTP.WithLogger(logger),
    codeClientHTTP.WithInstrumentor(instrumentor),
    codeClientHTTP.WithErrorReporter(errorReporter),
)
```

The HTTP client exposes a `Do` function.

#### Target

Use the target to record the target of a scan, which can be either a folder enhanced with repository metadata 
or a repository.

```go
import (
    codeClientScan  "github.com/snyk/code-client-go/scan"
)

target, _ := codeClientScan.NewRepositoryTarget(path)

target, _ := codeClientScan.NewRepositoryTarget(path, codeClientScan.WithRepositoryUrl("https://github.com/snyk/code-client-go.git"))
```

#### Tracker Factory

Use the tracker factory to generate a tracker used to update the consumer of the client with frequent progress updates. 

The tracker either exposes an interface with two `Begin` and `End` functions or an implementation that doesn't do anything.

```go
import (
    codeClientScan  "github.com/snyk/code-client-go/scan"
)

trackerFactory := codeClientScan.NewNoopTrackerFactory()

tracker := trackerFactory.GenerateTracker()
tracker.Begin()
...
tracker.End()
```

#### Configuration

Implement the `config.Config` interface to configure the Snyk Code API client from applications.

#### Code Scanner

Use the Code Scanner to trigger a scan for a Snyk Code workspace using the Bundle Manager.

The Code Scanner exposes scanning functions including `UploadAndAnalyzeWithOptions` for flexible analysis:

```go
import (
    codeClient  "github.com/snyk/code-client-go"
)

config := newConfigForMyApp()
codeScanner := codeClient.NewCodeScanner(
    config,
    httpClient,
    codeClient.WithTrackerFactory(trackerFactory),
    codeClient.WithLogger(logger),
    codeClient.WithFlow("cli_test"),
)

// For local code analysis
result, metadata, err := codeScanner.UploadAndAnalyzeWithOptions(ctx, requestId, target, files, changedFiles)

// For remote code analysis (with project reporting)
result, metadata, err := codeScanner.AnalyzeRemote(ctx, codeClient.ReportRemoteTest(projectId, commitId))
```

#### Observability

Under [./observability](./observability) we have defined some observability interfaces which allows consumers of the library to inject their own observability implementations as long as they follow the defined interfaces.

## Contributing

To ensure the long-term stability and quality of this project, we are moving to a closed-contribution model effective August 2025. This change allows our core team to focus on a centralized development roadmap and rigorous quality assurance, which is essential for a component with such extensive usage.

All of our development will remain public for transparency. We thank the community for its support and valuable contributions.

## Getting Support

GitHub issues have been disabled on this repository as part of our move to a closed-contribution model. The Snyk support team does not actively monitor GitHub issues on any Snyk development project.

For help with the Snyk CLI or Snyk in general, please use the [Snyk support page](https://support.snyk.io/), which is the fastest way to get assistance.