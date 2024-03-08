package observability

type Logger interface {
	Error(err error, fields LoggerFields, userMessage string)
	Info(fields LoggerFields, userMessage string)
	Debug(err error, fields LoggerFields, userMessage string)
	Trace(fields LoggerFields, userMessage string)
}

type LoggerFields map[string]interface{}
