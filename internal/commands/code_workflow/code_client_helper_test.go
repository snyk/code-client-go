package code_workflow

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/code-client-go/pkg/code/sast_contract"
)

func Test_SnykCodeApi(t *testing.T) {
	t.Run("derives deeproxy host from API URL when SCLE is disabled", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(configuration.API_URL, "https://api.snyk.io")
		c := &codeClientConfig{localConfiguration: config}
		assert.Equal(t, "https://deeproxy.snyk.io", c.SnykCodeApi())
	})

	t.Run("returns the local engine URL when SCLE is enabled", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(configuration.API_URL, "https://api.snyk.io")
		config.Set(ConfigurationSlceEnabled, true)
		config.Set(ConfigurationSastSettings, &sast_contract.SastResponse{
			LocalCodeEngine: sast_contract.LocalCodeEngine{
				Enabled: true,
				Url:     "https://local-engine.example.com",
			},
		})
		c := &codeClientConfig{localConfiguration: config}
		assert.Equal(t, "https://local-engine.example.com", c.SnykCodeApi())
	})

	t.Run("returns empty when SCLE is enabled but the URL is empty", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(configuration.API_URL, "https://api.snyk.io")
		config.Set(ConfigurationSlceEnabled, true)
		config.Set(ConfigurationSastSettings, &sast_contract.SastResponse{
			LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: true},
		})
		c := &codeClientConfig{localConfiguration: config}
		assert.Empty(t, c.SnykCodeApi())
	})

	t.Run("returns empty when SCLE is enabled but settings are missing", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(configuration.API_URL, "https://api.snyk.io")
		config.Set(ConfigurationSlceEnabled, true)
		c := &codeClientConfig{localConfiguration: config}
		assert.Empty(t, c.SnykCodeApi())
	})
}

func Test_GetReportType(t *testing.T) {
	t.Run("no repport", func(t *testing.T) {
		config := configuration.NewWithOpts()
		actualMode, err := GetReportMode(config)
		assert.Equal(t, noReport, actualMode)
		assert.NoError(t, err)
	})

	t.Run("remote report", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationReportFlag, true)
		config.Set(ConfigurationProjectId, "remote")
		config.Set(ConfigurationCommitId, "commit")
		actualMode, err := GetReportMode(config)
		assert.Equal(t, remoteCode, actualMode)
		assert.NoError(t, err)
	})

	t.Run("remote report with error", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationReportFlag, true)
		config.Set(ConfigurationProjectId, "remote")
		actualMode, err := GetReportMode(config)
		assert.Equal(t, noReport, actualMode)
		assert.Error(t, err)
	})

	t.Run("local report", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationReportFlag, true)
		config.Set(ConfigurationProjectName, "hello")
		actualMode, err := GetReportMode(config)
		assert.Equal(t, localCode, actualMode)
		assert.NoError(t, err)
	})

	t.Run("local report with error", func(t *testing.T) {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationReportFlag, true)
		actualMode, err := GetReportMode(config)
		assert.Equal(t, noReport, actualMode)
		assert.Error(t, err)
	})
}
