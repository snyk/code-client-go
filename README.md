
# code-client-go

A library that exposes scanning capabilities for Snyk Code that can be used in the [Snyk CLI](https://github.com/snyk/cli) as well as Snyk IDE plugins using the [Snyk Language Server](https://github.com/snyk/snyk-ls).

## Installation

```shell script
$ go get github.com/snyk/code-client-go
```

## Usage

### HTTP Client

Use the HTTP client to make HTTP requests with configured retriable codes and authorisation headers for Snyk Rest APIs.

Implement the `github.com/snyk/code-client-go/http.Config` interface to configure the Snyk Code API client from applications.

Provide a net/http.Client factory to customize the underlying HTTP protocol behavior (timeouts, etc).

```go
import (
    "net/http"

    "github.com/rs/zerolog"
    codehttp "github.com/snyk/code-client-go/http"
)

logger := zerlog.NewLogger(...)
config := newConfigForMyApp()
httpClient := codehttp.NewHTTPClient(logger, config, func() *http.Client { return http.DefaultClient }, codeInstrumentor, codeErrorReporter)
```

The HTTP client exposes a `DoCall` function.

### Configuration

Implement the `http.Config` interface to configure the Snyk Code API client from applications.

### Snyk Code Client

Use the Snyk Code Client to make calls to the DeepCode API using the `httpClient` HTTP client created above.

```go
snykCode := deepcode.NewSnykCodeClient(logger, httpClient, testutil.NewTestInstrumentor())
```

The Snyk Code Client exposes the following functions:
- `GetFilters`
- `CreateBundle`
- `ExtendBundle`

### Bundle Manager

Use the Bundle Manager to create bundles using the `snykCode` Snyk Code Client created above and then to extend it by uploading more files to it.

```go
bundleManager := bundle.NewBundleManager(logger, snykCode, testutil.NewTestInstrumentor(), testutil.NewTestCodeInstrumentor())
```

The Bundle Manager exposes the following functions:
- `Create`
- `Upload`

### Code Scanner

Use the Code Scanner to trigger a scan for a Snyk Code workspace using the Bundle Manager created above.
The Code Scanner exposes a `UploadAndAnalyze` function, which can be used like this:

```go
codeScanner := codeclient.NewCodeScanner(
    bundleManager,
    testutil.NewTestInstrumentor(),
    testutil.NewTestErrorReporter(),
    logger,
)
codeScanner.UploadAndAnalyze(context.Background(), "path/to/workspace", channelForWalkingFiles, changedFiles)
```


### Observability

Under [./observability](./observability) we have defined some observability interfaces which allows consumers of the library to inject their own observability implementations as long as they follow the defined interfaces.
