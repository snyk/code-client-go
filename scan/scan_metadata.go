package scan

import "context"

type contextKey string

const InitiatorKey = contextKey("initiator")

type ResultMetaData struct {
	FindingsUrl string
	WebUiUrl    string
}

type ScanSource string

func (s ScanSource) String() string {
	return string(s)
}

const (
	LLM ScanSource = "LLM"
	IDE ScanSource = "IDE"
	CLI ScanSource = "CLI"
)

type scanSourceKeyType int

var scanSourceKey scanSourceKeyType

func NewContextWithScanSource(ctx context.Context, source ScanSource) context.Context {
	return context.WithValue(ctx, scanSourceKey, source)
}

func ScanSourceFromContext(ctx context.Context) (ScanSource, bool) {
	s, ok := ctx.Value(scanSourceKey).(ScanSource)
	return s, ok
}
