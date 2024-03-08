package observability

type ErrorReporter interface {
	FlushErrorReporting()
	CaptureError(err error) bool
	CaptureErrorAndReportAsIssue(path string, err error) bool
}
