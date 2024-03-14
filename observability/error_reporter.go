package observability

type ErrorReporter interface {
	FlushErrorReporting()
	CaptureError(err error, options ErrorReporterOptions) bool
}

type ErrorReporterOptions struct {
	errorDiagnosticPath string
}
