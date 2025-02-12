package llm

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/http"
	"github.com/stretchr/testify/assert"
)

func TestDeepcodeLLMBinding_Explain_Smoke(t *testing.T) {
	t.Skipf("can not run automatically")
	logger := zerolog.Nop()

	binding := NewDeepcodeLLMBinding(
		WithHTTPClient(func() http.HTTPClient { return http.NewHTTPClient(http.NewDefaultClientFactory()) }),
		WithLogger(&logger),
	)
	outputChain := make(chan string)
	err := binding.Explain("{}", HTML, outputChain)
	assert.NoError(t, err)
}
