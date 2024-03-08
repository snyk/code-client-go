package observability

type Tracker interface {
	BeginWithMessage(title, message string)
	EndWithMessage(message string)
	BeginUnquantifiableLength(title, message string)
	End()
	Report(percentage int)
}
