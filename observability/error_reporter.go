package observability

// ErrorReporter exposes functions using for reporting errors.
type ErrorReporter interface {
	FlushErrorReporting()
	CaptureError(err error) bool
	CaptureErrorAndReportAsIssue(path string, err error) bool
}
