package observability

// Tracker exposes functions that are used for tracking progress.
type Tracker interface {
	BeginWithMessage(title, message string)
	EndWithMessage(message string)
	BeginUnquantifiableLength(title, message string)
	End()
	Report(percentage int)
}
