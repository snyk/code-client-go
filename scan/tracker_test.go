package scan_test

import (
	"github.com/snyk/code-client-go/scan"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func Test_Tracker_Begin(t *testing.T) {
	var testProgressChannels = make(scan.ProgressChannels, 10000)

	tracker := scan.NewTracker(testProgressChannels)
	tracker.Begin("title", "message")

	hasBegun := false
	assert.Eventually(
		t,
		func() bool {
			for {
				select {
				case p := <-testProgressChannels:
					switch p.Kind {
					case scan.ProgressKindInit:
						hasBegun = true
						return false
					case scan.ProgressKindBegin:
						if !hasBegun {
							return false
						}
						return "title" == p.Title && "message" == p.Message
					case scan.ProgressKindReport:
						return false
					case scan.ProgressKindEnd:
						return false
					}
				default:
					break
				}
				break //nolint:staticcheck // we want to do this until a message is seen
			}
			return false
		},
		5*time.Second,
		10*time.Millisecond,
	)
}

func Test_Tracker_Report(t *testing.T) {
	var testProgressChannels = make(scan.ProgressChannels, 10000)

	tracker := scan.NewTracker(testProgressChannels)
	tracker.Report("message")

	assert.Eventually(
		t,
		func() bool {
			for {
				select {
				case p := <-testProgressChannels:
					switch p.Kind {
					case scan.ProgressKindInit:
						return false
					case scan.ProgressKindBegin:
						return false
					case scan.ProgressKindReport:
						return "message" == p.Message
					case scan.ProgressKindEnd:
						return false
					}
				default:
					break
				}
				break //nolint:staticcheck // we want to do this until a message is seen
			}
			return false
		},
		5*time.Second,
		10*time.Millisecond,
	)
}

func Test_Tracker_End(t *testing.T) {
	var testProgressChannels = make(scan.ProgressChannels, 10000)

	tracker := scan.NewTracker(testProgressChannels)
	tracker.End("message")
	assert.Eventually(
		t,
		func() bool {
			for {
				select {
				case p := <-testProgressChannels:
					switch p.Kind {
					case scan.ProgressKindInit:
						return false
					case scan.ProgressKindBegin:
						return false
					case scan.ProgressKindReport:
						return false
					case scan.ProgressKindEnd:
						return "message" == p.Message
					}
				default:
					break
				}
				break //nolint:staticcheck // we want to do this until a message is seen
			}
			return false
		},
		5*time.Second,
		10*time.Millisecond,
	)
}
