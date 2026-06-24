package code_workflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
)

func Test_defaultAnalyzeFunction_reportNotSupportedWithSCLE(t *testing.T) {
	logger := zerolog.Nop()

	t.Run("errors when --report is requested for an SCLE org", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationReportFlag, true)
		config.Set(ConfigurationProjectName, "my-project") // makes report mode localCode
		config.Set(ConfigurationSlceEnabled, true)

		_, _, _, err := defaultAnalyzeFunction(context.Background(), t.TempDir(), nil, &logger, config, nil)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Snyk Code Local Engine")
	})
}

func Test_defaultAnalyzeFunction_usesLocalEngineLegacyEndpoints(t *testing.T) {
	logger := zerolog.Nop()
	const bundleHash = "legacy-bundle-hash"

	var (
		mu       sync.Mutex
		requests []string
	)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Method+" "+r.URL.Path)
		mu.Unlock()

		assert.Equal(t, "test-org", r.Header.Get("snyk-org-name"))

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/filters":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"configFiles":[],"extensions":[".js"]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/bundle":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"bundleHash":"` + bundleHash + `","missingFiles":["app.js"]}`))
		case r.Method == http.MethodPut && r.URL.Path == "/bundle/"+bundleHash:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"bundleHash":"` + bundleHash + `","missingFiles":[]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/analysis":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{
				"type":"sarif",
				"progress":1.0,
				"status":"COMPLETE",
				"timing":{"fetchingCode":1,"queue":1,"analysis":1},
				"coverage":[],
				"sarif":{"version":"2.1.0","runs":[]}
			}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	path := t.TempDir()
	writeFile(t, filepath.Join(path, "app.js"))

	config := configuration.NewWithOpts()
	config.Set(configuration.API_URL, "https://api.snyk.io")
	config.Set(configuration.ORGANIZATION, "test-org")
	config.Set(configuration.MAX_THREADS, 1)
	config.Set(configuration.FLAG_REMOTE_REPO_URL, "https://github.com/snyk/nodejs-goof")
	config.Set(ConfigurationSlceEnabled, true)
	config.Set(ConfigurationSastSettings, &sast_contract.SastResponse{
		SastEnabled: true,
		LocalCodeEngine: sast_contract.LocalCodeEngine{
			Enabled: true,
			Url:     server.URL,
		},
	})

	result, actualBundleHash, resultMetaData, err := defaultAnalyzeFunction(
		context.Background(),
		path,
		func() *http.Client { return server.Client() },
		&logger,
		config,
		ui.DefaultUi(),
	)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "COMPLETE", result.Status)
	assert.Equal(t, bundleHash, actualBundleHash)
	assert.Nil(t, resultMetaData)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{
		"GET /filters",
		"POST /bundle",
		"PUT /bundle/" + bundleHash,
		"POST /analysis",
	}, requests)
}

type fakeLegacyCodeScanner struct {
	called        bool
	shardKey      string
	statusMessage string
	response      *sarif.SarifResponse
	bundleHash    string
}

type fakeTarget struct {
	path string
}

func (f fakeTarget) GetPath() string {
	return f.path
}

func (f *fakeLegacyCodeScanner) Upload(context.Context, string, scan.Target, <-chan string, map[string]bool) (bundle.Bundle, error) {
	panic("Upload should not be called by analyzeWithLegacyEngine")
}

func (f *fakeLegacyCodeScanner) UploadAndAnalyze(context.Context, string, scan.Target, <-chan string, map[string]bool) (*sarif.SarifResponse, string, error) {
	panic("UploadAndAnalyze should not be called by analyzeWithLegacyEngine")
}

func (f *fakeLegacyCodeScanner) UploadAndAnalyzeLegacy(
	_ context.Context,
	_ string,
	_ scan.Target,
	shardKey string,
	_ <-chan string,
	_ map[string]bool,
	statusChannel chan<- scan.LegacyScanStatus,
) (*sarif.SarifResponse, string, error) {
	f.called = true
	f.shardKey = shardKey
	statusChannel <- scan.LegacyScanStatus{Message: f.statusMessage}
	close(statusChannel)
	return f.response, f.bundleHash, nil
}

func Test_analyzeWithLegacyEngine(t *testing.T) {
	logger := zerolog.Nop()
	response := &sarif.SarifResponse{Status: "COMPLETE"}
	scanner := &fakeLegacyCodeScanner{
		response:      response,
		bundleHash:    "legacy-bundle-hash",
		statusMessage: "analysis complete",
	}

	files := make(chan string)
	close(files)

	actualResponse, actualBundleHash, actualMetaData, err := analyzeWithLegacyEngine(
		context.Background(),
		scanner,
		"request-id",
		fakeTarget{path: t.TempDir()},
		files,
		map[string]bool{},
		&logger,
	)

	assert.NoError(t, err)
	assert.True(t, scanner.called)
	assert.Empty(t, scanner.shardKey)
	assert.Same(t, response, actualResponse)
	assert.Equal(t, "legacy-bundle-hash", actualBundleHash)
	assert.Nil(t, actualMetaData)
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
