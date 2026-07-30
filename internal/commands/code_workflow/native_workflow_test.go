package code_workflow

import (
	"bytes"
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

	codeclient "github.com/snyk/code-client-go"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
)

func recordedExtensions(t *testing.T, a analytics.Analytics) map[string]interface{} {
	t.Helper()

	body, err := analytics.GetV2InstrumentationObject(a.GetInstrumentation())
	require.NoError(t, err)

	if body.Data.Attributes.Interaction.Extension == nil {
		return map[string]interface{}{}
	}
	return *body.Data.Attributes.Interaction.Extension
}

func Test_defaultAnalyzeFunction_usesFileUploadApi(t *testing.T) {
	logs := &bytes.Buffer{}
	logger := zerolog.New(logs)
	revID := uuid.NewString()

	var (
		mu                                                 sync.Mutex
		filtersHit, createHit, uploadHit, sealHit, testHit bool
		uploadRequestIds                                   []string
		testRequestId                                      string
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
			uploadRequestIds = append(uploadRequestIds, r.Header.Get("snyk-request-id"))
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/upload_revisions"):
			createHit = true
			uploadRequestIds = append(uploadRequestIds, r.Header.Get("snyk-request-id"))
			w.WriteHeader(http.StatusCreated)
			_, _ = fmt.Fprintf(w, `{"data":{"id":%q,"type":"upload_revision","attributes":{"revision_type":"snapshot","sealed":false}}}`, revID)
		case r.Method == http.MethodPatch && strings.Contains(r.URL.Path, "/upload_revisions/"):
			sealHit = true
			uploadRequestIds = append(uploadRequestIds, r.Header.Get("snyk-request-id"))
			_, _ = fmt.Fprintf(w, `{"data":{"id":%q,"type":"upload_revision","attributes":{"revision_type":"snapshot","sealed":true}}}`, revID)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tests"):
			// The test service is invoked against the uploaded revision; its happy
			// path is covered by the analysis package tests, so it is stubbed here.
			testHit = true
			testRequestId = r.Header.Get("snyk-request-id")
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

	analyticsClient := analytics.New()

	result, _, _, err := defaultAnalyzeFunction(
		context.Background(),
		path,
		func() *http.Client { return server.Client() },
		&logger,
		config,
		ui.DefaultUi(),
		analyticsClient,
	)

	require.NoError(t, err)
	assert.Nil(t, result)

	extensions := recordedExtensions(t, analyticsClient)
	assert.Equal(t, codeclient.BackendFileUploadApi, extensions[AnalyticsFileUploadBackend])
	assert.Equal(t, true, extensions["upload_success"])
	assert.Contains(t, extensions, "upload_duration_ms")

	// The revision id is the only identifier tying a scan to the content that was uploaded for it.
	assert.Contains(t, logs.String(), "Snyk Code upload revision created")
	assert.Contains(t, logs.String(), revID)

	mu.Lock()
	defer mu.Unlock()
	assert.True(t, filtersHit)
	assert.True(t, createHit)
	assert.True(t, uploadHit)
	assert.True(t, sealHit)
	assert.True(t, testHit)

	// The scan's request id is generated inside defaultAnalyzeFunction, so assert the property
	// that was broken instead: every upload call correlates to the same scan.
	require.Len(t, uploadRequestIds, 3)
	assert.NotEmpty(t, uploadRequestIds[0])
	for _, requestId := range uploadRequestIds[1:] {
		assert.Equal(t, uploadRequestIds[0], requestId)
	}
	assert.Equal(t, uploadRequestIds[0], testRequestId)
}

func Test_defaultAnalyzeFunction_recordsFailedFileUploadApiUpload(t *testing.T) {
	logger := zerolog.Nop()

	var (
		mu                 sync.Mutex
		createHit, testHit bool
		createRequestId    string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/filters":
			_, _ = w.Write([]byte(`{"configFiles":[],"extensions":[".js"]}`))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/upload_revisions"):
			// Creating the revision fails, so nothing is ever uploaded or sealed.
			// 403 rather than 500 because the http client retries 5xx (see retryErrorCodes).
			createHit = true
			createRequestId = r.Header.Get("snyk-request-id")
			w.WriteHeader(http.StatusForbidden)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/tests"):
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

	analyticsClient := analytics.New()

	result, _, _, err := defaultAnalyzeFunction(
		context.Background(),
		path,
		func() *http.Client { return server.Client() },
		&logger,
		config,
		ui.DefaultUi(),
		analyticsClient,
	)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "error uploading files")
	assert.Nil(t, result)

	extensions := recordedExtensions(t, analyticsClient)
	assert.Equal(t, codeclient.BackendFileUploadApi, extensions[AnalyticsFileUploadBackend])
	assert.Equal(t, false, extensions["upload_success"])
	assert.Contains(t, extensions, "upload_duration_ms")

	mu.Lock()
	defer mu.Unlock()
	assert.True(t, createHit)
	assert.NotEmpty(t, createRequestId)
	assert.False(t, testHit, "the analysis must not run when the upload failed")
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
