package code_workflow

import (
	"errors"
	"strings"
	"time"

	"github.com/snyk/go-application-framework/pkg/configuration"

	"github.com/snyk/code-client-go/pkg/code/sast_contract"
)

var defaultSnykCodeTimeout = 12 * time.Hour

type codeClientConfig struct {
	localConfiguration configuration.Configuration
}

func (c *codeClientConfig) Organization() string {
	return c.localConfiguration.GetString(configuration.ORGANIZATION)
}

func (c *codeClientConfig) IsFedramp() bool {
	return c.localConfiguration.GetBool(configuration.IS_FEDRAMP)
}

func (c *codeClientConfig) SnykCodeApi() string {
	// When Snyk Code Local Engine (SCLE) is enabled, requests must go to the
	// local engine endpoint advertised in the SAST settings rather than the
	// cloud deeproxy host derived from the API URL.
	if c.localConfiguration.GetBool(ConfigurationSlceEnabled) {
		if localEngineURL := c.localCodeEngineURL(); localEngineURL != "" {
			return localEngineURL
		}
	}
	return strings.ReplaceAll(c.localConfiguration.GetString(configuration.API_URL), "api", "deeproxy")
}

// localCodeEngineURL returns the Snyk Code Local Engine URL from the cached SAST
// settings, or an empty string if the settings are unavailable or unset.
func (c *codeClientConfig) localCodeEngineURL() string {
	settings, ok := c.localConfiguration.Get(ConfigurationSastSettings).(*sast_contract.SastResponse)
	if !ok || settings == nil {
		return ""
	}
	return settings.LocalCodeEngine.Url
}

func (c *codeClientConfig) SnykApi() string {
	return c.localConfiguration.GetString(configuration.API_URL)
}

func (c *codeClientConfig) SnykCodeAnalysisTimeout() time.Duration {
	if !c.localConfiguration.IsSet(configuration.TIMEOUT) {
		return defaultSnykCodeTimeout
	}
	timeoutInSeconds := c.localConfiguration.GetInt(configuration.TIMEOUT)
	return time.Duration(timeoutInSeconds) * time.Second
}

func GetReportMode(config configuration.Configuration) (reportType, error) {
	reportEnabled := config.GetBool(ConfigurationReportFlag)
	if !reportEnabled {
		return noReport, nil
	}

	if len(config.GetString(ConfigurationProjectId)) > 0 && len(config.GetString(ConfigurationCommitId)) == 0 {
		return noReport, errors.New("\"commit-id\" must be provided for \"report\"")
	}

	if len(config.GetString(ConfigurationProjectId)) > 0 {
		return remoteCode, nil
	}

	if len(config.GetString(ConfigurationProjectName)) == 0 {
		return noReport, errors.New("\"project-name\" must be provided for \"report\"")
	}

	return localCode, nil
}
