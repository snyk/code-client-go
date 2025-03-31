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
	if errEndpoint != nil {
		// time to panic, as our default should never be invalid
		panic(errEndpoint)
	}

	err := binding.Explain(context.Background(), AIRequest{Id: uuid.New().String(), Input: "{}", Endpoint: endpoint}, HTML, outputChain)
	assert.NoError(t, err)
}
