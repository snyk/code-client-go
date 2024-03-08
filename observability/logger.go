package observability

// Logger exposes functions used for logging progress.
type Logger interface {
	Error(err error, fields LoggerFields, userMessage string)
	Info(fields LoggerFields, userMessage string)
	Debug(err error, fields LoggerFields, userMessage string)
	Trace(fields LoggerFields, userMessage string)
}

// LoggerFields contains fields to enhance logs with.
type LoggerFields map[string]interface{}
