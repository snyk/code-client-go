
# code-client-go

A library that exposes scanning capabilities for Snyk Code that can be used in the [Snyk CLI](https://github.com/snyk/cli) as well as Snyk IDE plugins using the [Snyk Language Server](https://github.com/snyk/snyk-ls).

## Installation

```shell script
$ go get github.com/snyk/code-client-go
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

### Configuration

Implement the `config.Config` interface to configure the Snyk Code API client from applications.

### Code Scanner

Use the Code Scanner to trigger a scan for a Snyk Code workspace using the Bundle Manager created above.

The Code Scanner exposes a `UploadAndAnalyze` function, which can be used like this:

```go
config := newConfigForMyApp()
codeScanner := code.NewCodeScanner(
    httpClient,
    config,
    codeClientHTTP.WithLogger(logger),
    codeClientHTTP.WithInstrumentor(instrumentor),
    codeClientHTTP.WithErrorReporter(errorReporter),
)
code.UploadAndAnalyze(context.Background(), requestId, "path/to/workspace", channelForWalkingFiles, changedFiles)
```


### Observability

Under [./observability](./observability) we have defined some observability interfaces which allows consumers of the library to inject their own observability implementations as long as they follow the defined interfaces.
