package contributorbilling_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/contributorbilling"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/stretchr/testify/require"

	billing "github.com/snyk/code-client-go/internal/contributorbilling"
)

func TestEmitProject(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		requests []map[string]any
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)

		var payload map[string]any
		require.NoError(t, json.Unmarshal(body, &payload))

		mu.Lock()
		requests = append(requests, payload)
		mu.Unlock()

		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	ctrl := gomock.NewController(t)
	logger := zerolog.Nop()
	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.ORGANIZATION, "11111111-1111-1111-1111-111111111111")
	config.Set(configuration.AUTHENTICATION_TOKEN, "test-token")

	networkAccess := mocks.NewMockNetworkAccess(ctrl)
	networkAccess.EXPECT().GetHttpClient().Return(server.Client()).AnyTimes()

	invocation := mocks.NewMockInvocationContext(ctrl)
	invocation.EXPECT().GetConfiguration().Return(config).AnyTimes()
	invocation.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()
	invocation.EXPECT().GetNetworkAccess().Return(networkAccess).AnyTimes()

	billing.EmitProject(
		context.Background(),
		invocation,
		"22222222-2222-2222-2222-222222222222",
		"/tmp/repo",
	)

	require.True(t, contributorbilling.WaitWithTimeout(2*time.Second))

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, requests, 1)
}
