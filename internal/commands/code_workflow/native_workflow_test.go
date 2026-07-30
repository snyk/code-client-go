package code_workflow

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
)

func Test_defaultAnalyzeFunction_usesFileUploadApi(t *testing.T) {
	logger := zerolog.Nop()
	revID := uuid.NewString()

	var (
		mu                                                 sync.Mutex
		filtersHit, createHit, uploadHit, sealHit, testHit bool
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/filters":
			filtersHit = true
			_, _ = w.Write([]byte(`{"configFiles":[],"extensions":[".js"]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/files"):
			uploadHit = true
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/upload_revisions"):
			createHit = true
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"data":{"id":%q,"type":"upload_revision","attributes":{"revision_type":"snapshot","sealed":false}}}`, revID)
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/upload_revisions/"):
			sealHit = true
			_, _ = fmt.Fprintf(w, `{"data":{"id":%q,"type":"upload_revision","attributes":{"revision_type":"snapshot","sealed":true}}}`, revID)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tests"):
			// The test service is invoked against the uploaded revision; its happy
			// path is covered by the analysis package tests, so it is stubbed here.
			testHit = true
			w.WriteHeader(http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	path := t.TempDir()
	writeFile(t, filepath.Join(path, "app.js"))

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.ORGANIZATION, uuid.NewString())
	config.Set(configuration.MAX_THREADS, 1)
	config.Set(configuration.FLAG_REMOTE_REPO_URL, "https://github.com/snyk/nodejs-goof")
	config.Set(ConfigurationUploadToFileUploadApi, true)

	result, _, _, err := defaultAnalyzeFunction(
		context.Background(),
		path,
		func() *http.Client { return server.Client() },
		&logger,
		config,
		ui.DefaultUi(),
	)

	require.NoError(t, err)
	assert.Nil(t, result)

	mu.Lock()
	defer mu.Unlock()
	assert.True(t, filtersHit)
	assert.True(t, createHit)
	assert.True(t, uploadHit)
	assert.True(t, sealHit)
	assert.True(t, testHit)
}

func writeFile(t *testing.T, filename string) {
	t.Helper()
	err := os.WriteFile(filename, []byte("hello"), 0644)
	assert.NoError(t, err)
}

func Test_determineAnalyzeInput(t *testing.T) {
	logger := zerolog.Nop()
	config := configuration.NewWithOpts()
	config.Set(configuration.FLAG_REMOTE_REPO_URL, "hello")
	config.Set(configuration.MAX_THREADS, 1)

	path := t.TempDir()
	filenames := []string{
		filepath.Join(path, "hello.txt"),
		filepath.Join(path, "world.txt"),
	}
	writeFile(t, filenames[0])
	writeFile(t, filenames[1])

	t.Run("given a folder", func(t *testing.T) {
		count := 0

		target, files, err := determineAnalyzeInput(path, config, &logger)
		assert.NoError(t, err)
		assert.NotNil(t, target)
		assert.NotNil(t, files)
		assert.Equal(t, path, target.GetPath())

		for file := range files {
			t.Log(file)
			count++
		}

		assert.Equal(t, 2, count)
	})

	t.Run("given a file", func(t *testing.T) {
		count := 0

		target, files, err := determineAnalyzeInput(filenames[1], config, &logger)
		assert.NoError(t, err)
		assert.NotNil(t, target)
		assert.NotNil(t, files)
		assert.Equal(t, path, target.GetPath())

		for file := range files {
			t.Log(file)
			count++
		}

		assert.Equal(t, 1, count)
	})
}

func Test_TrackUsage(t *testing.T) {
	trackUsageCalled := false
	org := "something"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.String(), "/v1/track-sast-usage/cli?org="+org) {
			trackUsageCalled = true
		}

		assert.Equal(t, http.MethodPost, r.Method)
		w.WriteHeader(http.StatusOK)
	}))

	config := configuration.NewWithOpts()
	config.Set(configuration.ORGANIZATION, org)
	config.Set(configuration.API_URL, server.URL)
	networkAccess := networking.NewNetworkAccess(config)

	// call method under test
	trackUsage(networkAccess, config)

	assert.True(t, trackUsageCalled)
}
