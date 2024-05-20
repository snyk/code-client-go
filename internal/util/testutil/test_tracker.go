package testutil

import (
	"github.com/snyk/code-client-go/scan"
)

type testTracker struct {
}

// NewTestTracker is used in pact testing.
func NewTestTracker() scan.Tracker {
	return &testTracker{}
}

func (t testTracker) Begin(title, message string) {
}

func (t testTracker) Report(message string) {
}

func (t testTracker) End(message string) {
}
