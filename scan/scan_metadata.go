package scan

type contextKey string

const InitiatorKey = contextKey("initiator")

type ResultMetaData struct {
	FindingsUrl string
	WebUiUrl    string
}
