package llm

import (
	"context"
	"fmt"
)

// FakeDeepCodeLLMBinding implements DeepCodeLLMBinding interface for testing purposes
type FakeDeepCodeLLMBindingImpl struct {
	Result      ExplainResult
	IsServerErr bool
}

var _ DeepCodeLLMBinding = &FakeDeepCodeLLMBindingImpl{}

// NewFakeDeepcodeLLMBinding creates a new instance of FakeDeepCodeLLMBinding
func NewFakeDeepcodeLLMBinding() *FakeDeepCodeLLMBindingImpl {
	return &FakeDeepCodeLLMBindingImpl{}
}

// ExplainWithOptions implements DeepCodeLLMBinding.ExplainWithOptions
func (f *FakeDeepCodeLLMBindingImpl) ExplainWithOptions(ctx context.Context, options ExplainOptions) (ExplainResult, error) {
	if f.IsServerErr {
		return nil, fmt.Errorf("failed to generate explanation due to server error with status code %d", 500)
	}

	return f.Result, nil
}

// Explain implements DeepCodeLLMBinding.Explain
func (f *FakeDeepCodeLLMBindingImpl) Explain(ctx context.Context, input AIRequest, format OutputFormat, output chan<- string) error {
	panic("unimplemented")
}

// PublishIssues implements DeepCodeLLMBinding.PublishIssues
func (f *FakeDeepCodeLLMBindingImpl) PublishIssues(ctx context.Context, issues []map[string]string) error {
	panic("unimplemented")
}
