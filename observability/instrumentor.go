package observability

import (
	"context"
)

// Instrumentor exposes functions used for adding instrumentation context to functions.
type Instrumentor interface {
	StartSpan(ctx context.Context, operation string) Span
	NewTransaction(
		ctx context.Context,
		txName string,
		operation string,
	) Span
	Finish(span Span)
}

// Span exposes functions that have context about functions.
type Span interface {
	SetTransactionName(name string)
	StartSpan(ctx context.Context)
	Finish()
	GetOperation() string
	GetTxName() string

	// GetTraceId Returns UUID of the trace
	GetTraceId() string
	Context() context.Context

	GetDurationMs() int64
}
