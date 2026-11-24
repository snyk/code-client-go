package scan

import "context"

type ResultMetaData struct {
	FindingsUrl string
	WebUiUrl    string
	ProjectId   string
	SnapshotId  string
	// SkippedFiles lists files that were left out of the upload, so the scan could not analyze them.
	// It is only filled for uploads through the file upload API.
	SkippedFiles []SkippedFile
}

// SkipReason says why a file was left out of an upload.
type SkipReason string

const (
	SkipReasonFileTooLarge SkipReason = "FILE_TOO_LARGE"
	SkipReasonPathTooLong  SkipReason = "PATH_TOO_LONG"
	SkipReasonOther        SkipReason = "OTHER"
)

// SkippedFile is a file that was left out of an upload, and why.
type SkippedFile struct {
	Path   string
	Reason SkipReason
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
