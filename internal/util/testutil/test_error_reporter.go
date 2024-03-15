package testutil

import (
	"github.com/snyk/code-client-go/observability"
)

type localErrorReporter struct {
}

// NewTestErrorReporter is used in pact testing.
func NewTestErrorReporter() observability.ErrorReporter {
	return &localErrorReporter{}
}

func (l localErrorReporter) FlushErrorReporting() {
}

func (l localErrorReporter) CaptureError(err error, options observability.ErrorReporterOptions) bool {
	return true
}
