package testutil

import (
	"context"

	"github.com/google/uuid"
	
	"github.com/snyk/code-client-go/observability"
)

type localInstrumentor struct {
}

// NewTestInstrumentor is used in pact testing.
func NewTestInstrumentor() observability.Instrumentor {
	return &localInstrumentor{}
}

func (i *localInstrumentor) Record(span observability.Span) {
}

func (i *localInstrumentor) Spans() []observability.Span {
	return []observability.Span{}
}

func (i *localInstrumentor) ClearSpans() {
}

func (i *localInstrumentor) StartSpan(ctx context.Context, operation string) observability.Span {
	return &testSpan{}
}

func (i *localInstrumentor) NewTransaction(ctx context.Context, txName string, operation string) observability.Span {
	return &testSpan{}
}

func (i *localInstrumentor) Finish(span observability.Span) {
}

type testSpan struct {
}

func (n *testSpan) GetDurationMs() int64 { return 0 }

func (n *testSpan) Finish() {
}
func (n *testSpan) SetTransactionName(string) {}
func (n *testSpan) StartSpan(context.Context) {
}

func (n *testSpan) GetOperation() string {
	return "test"
}
func (n *testSpan) GetTxName() string {
	return "test"
}
func (n *testSpan) GetTraceId() string {
	return uuid.New().String()
}

func (n *testSpan) Context() context.Context {
	return context.Background()
}
