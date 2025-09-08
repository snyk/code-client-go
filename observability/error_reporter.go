package observability

//go:generate go tool github.com/golang/mock/mockgen -destination=mocks/error_reporter.go -source=error_reporter.go -package mocks

type ErrorReporter interface {
	FlushErrorReporting()
	CaptureError(err error, options ErrorReporterOptions) bool
}

type ErrorReporterOptions struct {
	ErrorDiagnosticPath string
}
