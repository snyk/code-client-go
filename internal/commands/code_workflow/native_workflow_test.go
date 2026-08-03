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

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	codeclient "github.com/snyk/code-client-go"
	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/snyk/go-application-framework/pkg/configuration"
	gafmocks "github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/utils"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

// testInvocationContext builds the InvocationContext the analyze function pulls its dependencies
// out of. GetFileFilter mirrors the framework implementation, so file filtering is exercised for
// real rather than stubbed.
func testInvocationContext(
	t *testing.T,
	config configuration.Configuration,
	logger *zerolog.Logger,
	httpClientFunc func() *http.Client,
	userInterface ui.UserInterface,
	analyticsClient analytics.Analytics,
) workflow.InvocationContext {
	t.Helper()
	ctrl := gomock.NewController(t)

	networkAccess := gafmocks.NewMockNetworkAccess(ctrl)
	networkAccess.EXPECT().GetHttpClient().DoAndReturn(func() *http.Client {
		if httpClientFunc == nil {
			return nil
		}
		return httpClientFunc()
	}).AnyTimes()

	ictx := gafmocks.NewMockInvocationContext(ctrl)
	ictx.EXPECT().Context().Return(context.Background()).AnyTimes()
	ictx.EXPECT().GetConfiguration().Return(config).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(logger).AnyTimes()
	ictx.EXPECT().GetNetworkAccess().Return(networkAccess).AnyTimes()
	ictx.EXPECT().GetUserInterface().Return(userInterface).AnyTimes()
	ictx.EXPECT().GetAnalytics().Return(analyticsClient).AnyTimes()
	ictx.EXPECT().GetFileFilter(gomock.Any(), gomock.Any()).DoAndReturn(
		func(path string, options ...utils.FileFilterOption) *utils.FileFilter {
			return utils.NewFileFilter(path, logger, append([]utils.FileFilterOption{utils.WithConfig(config)}, options...)...)
		}).AnyTimes()

	return ictx
}

func Test_defaultAnalyzeFunction_reportNotSupportedWithSCLE(t *testing.T) {
	logger := zerolog.Nop()

	t.Run("errors when --report is requested for an SCLE org", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationReportFlag, true)
		config.Set(ConfigurationProjectName, "my-project") // makes report mode localCode
		config.Set(ConfigurationSlceEnabled, true)

		ictx := testInvocationContext(t, config, &logger, nil, nil, analytics.New())

		_, _, _, err := defaultAnalyzeFunction(ictx, t.TempDir())

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Snyk Code Local Engine")
	})
}

// recordedExtensions returns the analytics extension values the analysis recorded. Integers
// come back as float64 because the collector round-trips the extension map through JSON.
func recordedExtensions(t *testing.T, a analytics.Analytics) map[string]interface{} {
	t.Helper()

	body, err := analytics.GetV2InstrumentationObject(a.GetInstrumentation())
	require.NoError(t, err)

	if body.Data.Attributes.Interaction.Extension == nil {
		return map[string]interface{}{}
	}
	return *body.Data.Attributes.Interaction.Extension
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

		assert.Equal(t, "4a72d1db-b465-4764-99e1-ecedad03b06a", r.Header.Get("snyk-org-name"))

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
	config.Set(configuration.ORGANIZATION, "4a72d1db-b465-4764-99e1-ecedad03b06a")
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

	analyticsClient := analytics.New()

	ictx := testInvocationContext(t, config, &logger, func() *http.Client { return server.Client() }, ui.DefaultUi(), analyticsClient)

	result, actualBundleHash, resultMetaData, err := defaultAnalyzeFunction(ictx, path)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "COMPLETE", result.Status)
	assert.Equal(t, bundleHash, actualBundleHash)
	assert.Nil(t, resultMetaData)

	// SCLE returns before the file upload backend is chosen, so nothing is recorded.
	assert.NotContains(t, recordedExtensions(t, analyticsClient), AnalyticsFileUploadBackend)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, []string{
		"GET /filters",
		"POST /bundle",
		"PUT /bundle/" + bundleHash,
		"POST /analysis",
	}, requests)
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

	ictx := testInvocationContext(t, config, &logger, func() *http.Client { return server.Client() }, ui.DefaultUi(), analyticsClient)

	result, _, _, err := defaultAnalyzeFunction(ictx, path)

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

	ictx := testInvocationContext(t, config, &logger, func() *http.Client { return server.Client() }, ui.DefaultUi(), analyticsClient)

	result, _, _, err := defaultAnalyzeFunction(ictx, path)

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

		ictx := testInvocationContext(t, config, &logger, nil, nil, analytics.New())

		target, files, err := determineAnalyzeInput(ictx, path)
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

		ictx := testInvocationContext(t, config, &logger, nil, nil, analytics.New())

		target, files, err := determineAnalyzeInput(ictx, filenames[1])
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

// Test_determineAnalyzeInput_usesInvocationContextFileFilter pins that filtering is obtained from
// the invocation context. Constructing a FileFilter directly would still compile and still filter,
// but would silently drop every configuration-gated behavior (the ignore-rule metacharacter fix,
// tracked-file handling), so nothing else in the suite would fail.
func Test_determineAnalyzeInput_usesInvocationContextFileFilter(t *testing.T) {
	logger := zerolog.Nop()
	config := configuration.NewWithOpts()
	config.Set(configuration.MAX_THREADS, 1)

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "app.js"))

	ctrl := gomock.NewController(t)
	ictx := gafmocks.NewMockInvocationContext(ctrl)
	ictx.EXPECT().Context().Return(context.Background()).AnyTimes()
	ictx.EXPECT().GetConfiguration().Return(config).AnyTimes()
	ictx.EXPECT().GetEnhancedLogger().Return(&logger).AnyTimes()

	// exactly once, rooted at the scanned directory
	ictx.EXPECT().GetFileFilter(dir, gomock.Any()).Times(1).DoAndReturn(
		func(path string, options ...utils.FileFilterOption) *utils.FileFilter {
			return utils.NewFileFilter(path, &logger, options...)
		})

	_, files, err := determineAnalyzeInput(ictx, dir)
	require.NoError(t, err)

	var found []string
	for f := range files {
		found = append(found, filepath.Base(f))
	}
	assert.Equal(t, []string{"app.js"}, found)
}
