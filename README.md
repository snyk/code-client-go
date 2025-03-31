# code-client-go

A library that exposes scanning capabilities for Snyk Code that can be used in the [Snyk CLI](https://github.com/snyk/cli) as well as Snyk IDE plugins using the [Snyk Language Server](https://github.com/snyk/snyk-ls).

## Installation

```shell script
$ go get github.com/snyk/code-client-go/v2
```

## Usage

### HTTP Client

Use the HTTP client to make HTTP requests with configured retriable codes and authorisation headers for Snyk Rest APIs.

You can either configure the client using the functional options pattern provided or by implementing the interfaces.

Provide a `net/http.Client` factory to customize the underlying HTTP protocol behavior (timeouts, etc).

```go
import (
    "net/http"

    "github.com/rs/zerolog"
    codeClientHTTP "github.com/snyk/code-client-go/v2/http"
    codeClientObservability  "github.com/snyk/code-client-go/v2/observability"
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

### Target

Use the target to record the target of a scan, which can be either a folder enhanced with repository metadata
or a repository.

```go
import (
    codeClientScan  "github.com/snyk/code-client-go/v2/scan"
)

target, _ := codeClientScan.NewRepositoryTarget(path)

target, _ := codeClientScan.NewRepositoryTarget(path, codeClientScan.WithRepositoryUrl("https://github.com/snyk/code-client-go/v2.git"))
```

### Tracker Factory

Use the tracker factory to generate a tracker used to update the consumer of the client with frequent progress updates.

The tracker either exposes an interface with two `Begin` and `End` functions or an implementation that doesn't do anything.

```go
import (
    codeClientScan  "github.com/snyk/code-client-go/v2/scan"
)

trackerFactory := codeClientScan.NewNoopTrackerFactory()

tracker := trackerFactory.GenerateTracker()
tracker.Begin()
...
tracker.End()
```

### Configuration

Implement the `config.Config` interface to configure the Snyk Code API client from applications.

### Code Scanner

Use the Code Scanner to trigger a scan for a Snyk Code workspace using the Bundle Manager created above.

The Code Scanner exposes a `UploadAndAnalyze` function, which can be used like this:

```go
import (
    codeClient  "github.com/snyk/code-client-go/v2"
)

config := newConfigForMyApp()
codeScanner := codeClient.NewCodeScanner(
    httpClient,
    config,
	codeClient.WithTrackerFactory(trackerFactory),
    codeClientHTTP.WithLogger(logger),
    codeClientHTTP.WithInstrumentor(instrumentor),
    codeClientHTTP.WithErrorReporter(errorReporter),
)
codeScanner.UploadAndAnalyze(context.Background(), requestId, target, channelForWalkingFiles, changedFiles)
```


### Observability

Under [./observability](./observability) we have defined some observability interfaces which allows consumers of the library to inject their own observability implementations as long as they follow the defined interfaces.
