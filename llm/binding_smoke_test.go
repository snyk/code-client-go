package llm

import (
	"context"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/code-client-go/http"
)

func TestDeepcodeLLMBinding_Explain_Smoke(t *testing.T) {
	t.Skipf("can not run automatically")
	logger := zerolog.Nop()

	binding := NewDeepcodeLLMBinding(
		WithHTTPClient(func() http.HTTPClient { return http.NewHTTPClient(http.NewDefaultClientFactory()) }),
		WithLogger(&logger),
	)
	outputChain := make(chan string)
	endpoint, errEndpoint := url.Parse(defaultEndpointURL)
	assert.NoError(t, errEndpoint)

	err := binding.Explain(context.Background(), AIRequest{Id: uuid.New().String(), Input: "{}", Endpoint: endpoint}, HTML, outputChain)
	assert.NoError(t, err)
}
