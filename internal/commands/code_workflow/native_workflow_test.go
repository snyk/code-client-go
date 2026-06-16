package code_workflow

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/networking"
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
