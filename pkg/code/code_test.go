package code

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
	"github.com/snyk/error-catalog-golang-public/code"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/internal/commands/code_workflow"
	"github.com/snyk/code-client-go/pkg/code/sast_contract"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/local_workflows/content_type"
	"github.com/snyk/go-application-framework/pkg/local_workflows/json_schemas"
	testutils "github.com/snyk/go-application-framework/pkg/local_workflows/test_utils"
	"github.com/snyk/go-application-framework/pkg/mocks"
	"github.com/snyk/go-application-framework/pkg/networking"
	"github.com/snyk/go-application-framework/pkg/ui"
	"github.com/snyk/go-application-framework/pkg/workflow"
)

func Test_Code_nativeImplementation_happyPath(t *testing.T) {
	numberOfArtifacts := rand.Int()
	expectedSummary := json_schemas.TestSummary{
		Results: []json_schemas.TestSummaryResult{
			{Severity: "high", Total: 3, Open: 2, Ignored: 1},
			{Severity: "medium", Total: 1, Open: 1},
			{Severity: "low", Total: 1, Open: 0, Ignored: 1},
		},
		Artifacts: numberOfArtifacts,
	}

	expectedRepoUrl := "https://hello.world"
	expectedPath := "/var/lib/something"
	expectedBundleHash := "abc123bundlehash"

	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	config.Set(configuration.FLAG_REMOTE_REPO_URL, expectedRepoUrl)
	config.Set(configuration.INPUT_DIRECTORY, expectedPath)

	networkAccess := networking.NewNetworkAccess(config)

	mockController := gomock.NewController(t)
	invocationContext := mocks.NewMockInvocationContext(mockController)
	invocationContext.EXPECT().GetConfiguration().Return(config)
	invocationContext.EXPECT().GetNetworkAccess().Return(networkAccess).AnyTimes()
	invocationContext.EXPECT().GetEnhancedLogger().Return(&zerolog.Logger{})
	invocationContext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("code"))
	invocationContext.EXPECT().GetUserInterface().Return(ui.DefaultUi())
	invocationContext.EXPECT().Context().Return(context.Background()).AnyTimes()

	analysisFunc := func(_ context.Context, path string, _ func() *http.Client, _ *zerolog.Logger, _ configuration.Configuration, _ ui.UserInterface) (*sarif.SarifResponse, string, *scan.ResultMetaData, error) {
		assert.Equal(t, expectedPath, path)
		suppressions := []sarif.Suppression{
			{
				Status: sarif.Accepted,
			},
		}
		response := &sarif.SarifResponse{
			Sarif: sarif.SarifDocument{
				Runs: []sarif.Run{
					{
						Results: []sarif.Result{
							{Level: "error"},
							{Level: "warning"},
						},
						Properties: sarif.RunProperties{
							Coverage: []struct {
								Files       int    `json:"files"`
								IsSupported bool   `json:"isSupported"`
								Lang        string `json:"lang"`
								Type        string `json:"type"`
							}{{
								Files:       numberOfArtifacts,
								IsSupported: true,
								Lang:        "",
								Type:        "",
							}},
						},
					},
					{
						Results: []sarif.Result{
							{Level: "error"},
							{Level: "error", Suppressions: suppressions},
						},
					},
					{
						Results: []sarif.Result{
							{Level: "note", Suppressions: suppressions},
						},
					},
				},
			},
		}
		return response, expectedBundleHash, &scan.ResultMetaData{}, nil
	}

	rs, err := code_workflow.EntryPointNative(invocationContext, analysisFunc)
	assert.NoError(t, err)
	assert.NotNil(t, rs)
	assert.Equal(t, 2, len(rs))

	for _, v := range rs {
		if v.GetContentType() == content_type.TEST_SUMMARY {
			actualSummary := &json_schemas.TestSummary{}
			err = json.Unmarshal(v.GetPayload().([]byte), actualSummary)
			assert.NoError(t, err)

			count := 0
			for _, expectedResult := range expectedSummary.Results {
				for _, actualResult := range actualSummary.Results {
					if expectedResult.Severity == actualResult.Severity {
						assert.Equal(t, expectedResult, actualResult)
						count++
					}
				}
			}
			assert.Equal(t, len(expectedSummary.Results), count)
			assert.Equal(t, expectedSummary.Artifacts, actualSummary.Artifacts)

			actualBundleHash, metaErr := v.GetMetaData(code_workflow.MetadataBundleHash)
			assert.NoError(t, metaErr)
			assert.Equal(t, expectedBundleHash, actualBundleHash)
		} else if v.GetContentType() == content_type.LOCAL_FINDING_MODEL {
			_, ok := v.GetPayload().([]byte)
			assert.True(t, ok)
		} else {
			assert.Fail(t, "unexpected data")
		}
	}
}

func Test_Code_nativeImplementation_analysisFails(t *testing.T) {
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	networkAccess := networking.NewNetworkAccess(config)

	mockController := gomock.NewController(t)
	invocationContext := mocks.NewMockInvocationContext(mockController)
	invocationContext.EXPECT().GetConfiguration().Return(config)
	invocationContext.EXPECT().GetNetworkAccess().Return(networkAccess).AnyTimes()
	invocationContext.EXPECT().GetEnhancedLogger().Return(&zerolog.Logger{})
	invocationContext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("code"))
	invocationContext.EXPECT().GetUserInterface().Return(ui.DefaultUi())
	invocationContext.EXPECT().Context().Return(context.Background()).AnyTimes()

	analysisFunc := func(context.Context, string, func() *http.Client, *zerolog.Logger, configuration.Configuration, ui.UserInterface) (*sarif.SarifResponse, string, *scan.ResultMetaData, error) {
		return nil, "", nil, fmt.Errorf("something went wrong")
	}

	rs, err := code_workflow.EntryPointNative(invocationContext, analysisFunc)
	assert.Error(t, err)
	assert.Nil(t, rs)
}

func Test_Code_nativeImplementation_analysisNil(t *testing.T) {
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	networkAccess := networking.NewNetworkAccess(config)

	mockController := gomock.NewController(t)
	invocationContext := mocks.NewMockInvocationContext(mockController)
	invocationContext.EXPECT().GetConfiguration().Return(config)
	invocationContext.EXPECT().GetNetworkAccess().Return(networkAccess).AnyTimes()
	invocationContext.EXPECT().GetEnhancedLogger().Return(&zerolog.Logger{})
	invocationContext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("code"))
	invocationContext.EXPECT().GetUserInterface().Return(ui.DefaultUi())
	invocationContext.EXPECT().Context().Return(context.Background()).AnyTimes()

	analysisFunc := func(_ context.Context, path string, _ func() *http.Client, _ *zerolog.Logger, _ configuration.Configuration, _ ui.UserInterface) (*sarif.SarifResponse, string, *scan.ResultMetaData, error) {
		return nil, "", nil, nil
	}

	rs, err := code_workflow.EntryPointNative(invocationContext, analysisFunc)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(rs))

	summary := findTestSummary(rs)
	dataErrors := summary.GetErrorList()
	assert.Equal(t, 1, len(dataErrors))
	assert.Equal(t, dataErrors[0].ErrorCode, code.NewUnsupportedProjectError("").ErrorCode)
}

func findTestSummary(rs []workflow.Data) workflow.Data {
	var summary workflow.Data
	for _, v := range rs {
		if v.GetContentType() == content_type.TEST_SUMMARY {
			summary = v
		}
	}
	return summary
}

func Test_Code_nativeImplementation_analysisEmpty(t *testing.T) {
	config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
	networkAccess := networking.NewNetworkAccess(config)

	mockController := gomock.NewController(t)

	t.Run("returns UnsupportedProjectError when no supported files", func(t *testing.T) {
		invocationContext := mocks.NewMockInvocationContext(mockController)
		invocationContext.EXPECT().GetConfiguration().Return(config)
		invocationContext.EXPECT().GetNetworkAccess().Return(networkAccess).AnyTimes()
		invocationContext.EXPECT().GetEnhancedLogger().Return(&zerolog.Logger{})
		invocationContext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("code"))
		invocationContext.EXPECT().GetUserInterface().Return(ui.DefaultUi())
		invocationContext.EXPECT().Context().Return(context.Background()).AnyTimes()

		analysisFunc := func(_ context.Context, path string, _ func() *http.Client, _ *zerolog.Logger, _ configuration.Configuration, _ ui.UserInterface) (*sarif.SarifResponse, string, *scan.ResultMetaData, error) {
			response := &sarif.SarifResponse{
				Sarif: sarif.SarifDocument{
					Runs: []sarif.Run{
						{
							Properties: sarif.RunProperties{
								Coverage: []struct {
									Files       int    `json:"files"`
									IsSupported bool   `json:"isSupported"`
									Lang        string `json:"lang"`
									Type        string `json:"type"`
								}{{
									Files:       0,
									IsSupported: false,
									Lang:        "",
									Type:        "",
								}},
							},
						},
					},
				},
			}
			return response, "", &scan.ResultMetaData{}, nil
		}

		rs, err := code_workflow.EntryPointNative(invocationContext, analysisFunc)
		assert.NoError(t, err)
		assert.Equal(t, len(rs), 2)

		summary := findTestSummary(rs)
		dataErrors := summary.GetErrorList()
		assert.Equal(t, 1, len(dataErrors))
		assert.Equal(t, dataErrors[0].ErrorCode, code.NewUnsupportedProjectError("").ErrorCode)
	})

	t.Run("returns no error when supported files fail to parse", func(t *testing.T) {
		invocationContext := mocks.NewMockInvocationContext(mockController)
		invocationContext.EXPECT().GetConfiguration().Return(config)
		invocationContext.EXPECT().GetNetworkAccess().Return(networkAccess).AnyTimes()
		invocationContext.EXPECT().GetEnhancedLogger().Return(&zerolog.Logger{})
		invocationContext.EXPECT().GetWorkflowIdentifier().Return(workflow.NewWorkflowIdentifier("code"))
		invocationContext.EXPECT().GetUserInterface().Return(ui.DefaultUi())
		invocationContext.EXPECT().Context().Return(context.Background()).AnyTimes()

		analysisFunc := func(_ context.Context, path string, _ func() *http.Client, _ *zerolog.Logger, _ configuration.Configuration, _ ui.UserInterface) (*sarif.SarifResponse, string, *scan.ResultMetaData, error) {
			response := &sarif.SarifResponse{
				Sarif: sarif.SarifDocument{
					Runs: []sarif.Run{
						{
							Properties: sarif.RunProperties{
								Coverage: []struct {
									Files       int    `json:"files"`
									IsSupported bool   `json:"isSupported"`
									Lang        string `json:"lang"`
									Type        string `json:"type"`
								}{{
									Files:       1,
									IsSupported: false,
									Lang:        "py",
									Type:        "FAILED_PARSING",
								}},
							},
						},
					},
				},
			}
			return response, "bundleHash", &scan.ResultMetaData{}, nil
		}
		rs, err := code_workflow.EntryPointNative(invocationContext, analysisFunc)
		assert.NoError(t, err)
		assert.Equal(t, len(rs), 2)

		summary := findTestSummary(rs)
		dataErrors := summary.GetErrorList()
		assert.Equal(t, 0, len(dataErrors))
	})
}

func Test_Code_InitDoesNotRegisterNativeFeatureFlagGate(t *testing.T) {
	config := configuration.NewWithOpts()
	engine := workflow.NewWorkFlowEngine(config)

	err := Init(engine)
	require.NoError(t, err)

	keys := config.AllKeys()
	assert.NotContains(t, keys, configuration.FF_CODE_CONSISTENT_IGNORES)
	assert.NotContains(t, keys, configuration.FF_CODE_NATIVE_IMPLEMENTATION)
}

func Test_registerLocalEngineAuthURL(t *testing.T) {
	logger := zerolog.Nop()

	withSettings := func(slceEnabled bool, url string) configuration.Configuration {
		config := configuration.NewWithOpts()
		config.Set(ConfigurationSlceEnabled, slceEnabled)
		config.Set(ConfigurationSastSettings, &sast_contract.SastResponse{
			LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: slceEnabled, Url: url},
		})
		return config
	}

	t.Run("registers the local engine URL when SCLE is enabled", func(t *testing.T) {
		config := withSettings(true, "https://scle.example.internal")
		registerLocalEngineAuthURL(config, &logger)
		assert.Equal(t, []string{"https://scle.example.internal"}, config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS))
	})

	t.Run("does nothing when SCLE is disabled", func(t *testing.T) {
		config := withSettings(false, "https://scle.example.internal")
		registerLocalEngineAuthURL(config, &logger)
		assert.Empty(t, config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS))
	})

	t.Run("does nothing when the local engine URL is empty", func(t *testing.T) {
		config := withSettings(true, "")
		registerLocalEngineAuthURL(config, &logger)
		assert.Empty(t, config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS))
	})

	t.Run("does not duplicate an already-registered URL", func(t *testing.T) {
		config := withSettings(true, "https://scle.example.internal")
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{"https://scle.example.internal"})
		registerLocalEngineAuthURL(config, &logger)
		assert.Equal(t, []string{"https://scle.example.internal"}, config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS))
	})

	t.Run("preserves existing additional auth URLs", func(t *testing.T) {
		config := withSettings(true, "https://scle.example.internal")
		config.Set(configuration.AUTHENTICATION_ADDITIONAL_URLS, []string{"https://other.example.internal"})
		registerLocalEngineAuthURL(config, &logger)
		assert.Equal(t, []string{"https://other.example.internal", "https://scle.example.internal"}, config.GetStringSlice(configuration.AUTHENTICATION_ADDITIONAL_URLS))
	})
}

// setupMockEngine creates a mock engine with basic expectations
func setupMockEngine(t *testing.T) *mocks.MockEngine {
	t.Helper()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	config := configuration.New()
	return setupMockEngineWithConfig(t, ctrl, config, false)
}

// setupMockEngineWithConfig creates a mock engine with the given configuration
func setupMockEngineWithConfig(t *testing.T, ctrl *gomock.Controller, config configuration.Configuration, withNetworkAccess bool) *mocks.MockEngine {
	t.Helper()

	mockEngine := mocks.NewMockEngine(ctrl)
	mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
	mockEngine.EXPECT().GetLogger().Return(&zerolog.Logger{}).AnyTimes()

	if withNetworkAccess {
		mockEngine.EXPECT().GetNetworkAccess().Return(networking.NewNetworkAccess(config)).AnyTimes()
	}

	return mockEngine
}

// setupMockServerForSastSettings creates a mock HTTP server that returns SAST settings
func setupMockServerForSastSettings(t *testing.T, sastEnabled, localCodeEngineEnabled bool) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.String(), "/v1/cli-config/settings/sast") {
			response := &sast_contract.SastResponse{
				SastEnabled: sastEnabled,
				LocalCodeEngine: sast_contract.LocalCodeEngine{
					Enabled: localCodeEngineEnabled,
				},
			}
			w.WriteHeader(http.StatusOK)
			if err := json.NewEncoder(w).Encode(response); err != nil {
				t.Errorf("failed to encode response: %v", err)
			}
		}
	}))
}

// setupMockServerWithError creates a mock HTTP server that returns an error
func setupMockServerWithError(t *testing.T) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
}

// setupMockEngineWithServer creates a mock engine configured with a test server
func setupMockEngineWithServer(t *testing.T, server *httptest.Server) (*mocks.MockEngine, configuration.Configuration) {
	t.Helper()

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	config := configuration.New()
	config.Set(configuration.API_URL, server.URL)
	config.Set(configuration.ORGANIZATION, "test-org")

	mockEngine := setupMockEngineWithConfig(t, ctrl, config, true)
	return mockEngine, config
}

func Test_getSastSettingsConfig(t *testing.T) {
	t.Run("callback returns existing value when provided", func(t *testing.T) {
		existingValue := &sast_contract.SastResponse{SastEnabled: true}

		mockEngine := setupMockEngine(t)
		result, err := getSastSettingsConfig(mockEngine)(mockEngine.GetConfiguration(), existingValue)
		assert.NoError(t, err)
		assert.Equal(t, existingValue, result, "Should return existing value when provided")
	})

	t.Run("callback fetches settings when existing value is nil", func(t *testing.T) {
		server := setupMockServerForSastSettings(t, true, true)
		defer server.Close()

		mockEngine, config := setupMockEngineWithServer(t, server)

		result, err := getSastSettingsConfig(mockEngine)(config, nil)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		sastResponse, ok := result.(*sast_contract.SastResponse)
		assert.True(t, ok, "result should be of type *sast_contract.SastResponse")
		assert.True(t, sastResponse.SastEnabled)
		assert.True(t, sastResponse.LocalCodeEngine.Enabled)
	})

	t.Run("adds organization dependency and clears cache on org change", func(t *testing.T) {
		testutils.CheckCacheRespectOrgDependency(
			t,
			ConfigurationSastSettings,
			func(isFirstCall bool) any {
				return &sast_contract.SastResponse{
					SastEnabled:     isFirstCall,
					LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: isFirstCall},
				}
			},
			Init,
			&sast_contract.SastResponse{
				SastEnabled:     true,
				LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: true},
			},
			&sast_contract.SastResponse{
				SastEnabled:     false,
				LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: false},
			},
		)
	})

	t.Run("callback returns error when API call fails and existing value is nil", func(t *testing.T) {
		server := setupMockServerWithError(t)
		defer server.Close()

		mockEngine, config := setupMockEngineWithServer(t, server)

		result, err := getSastSettingsConfig(mockEngine)(config, nil)
		assert.Error(t, err)
		assert.Nil(t, result)
	})

	t.Run("uses cloned config's org, API URL and network access", func(t *testing.T) {
		globalOrg := "00000000-0000-0000-0000-000000000001"
		clonedOrg := "00000000-0000-0000-0000-000000000002"
		globalAPIEndpoint := "https://api.snyk.io"
		cloneAPIEndpoint := "https://api.eu.snyk.io"

		// Track which org IDs and API URLs were requested
		var requestedOrgs []string
		var requestedAPIs []string

		httpClient := testutils.NewTestClient(func(req *http.Request) *http.Response {
			// Extract org from query string and API URL from request
			org := req.URL.Query().Get("org")
			apiUrl := "https://" + req.Host
			requestedOrgs = append(requestedOrgs, org)
			requestedAPIs = append(requestedAPIs, apiUrl)

			response := &sast_contract.SastResponse{
				SastEnabled: org == globalOrg, // Mock a different response per org
				LocalCodeEngine: sast_contract.LocalCodeEngine{
					Enabled: apiUrl == globalAPIEndpoint, // Mock a different response per API URL
				},
			}
			responseJSON, err := json.Marshal(response)
			require.NoError(t, err)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewBuffer(responseJSON)),
			}
		})

		ctrl := gomock.NewController(t)
		mockEngine := mocks.NewMockEngine(ctrl)
		mockNetworkAccess := mocks.NewMockNetworkAccess(ctrl)
		logger := zerolog.Logger{}

		config := configuration.NewWithOpts(configuration.WithAutomaticEnv())
		config.Set(configuration.API_URL, globalAPIEndpoint)
		config.Set(configuration.ORGANIZATION, globalOrg)

		mockEngine.EXPECT().GetConfiguration().Return(config).AnyTimes()
		mockEngine.EXPECT().GetLogger().Return(&logger).AnyTimes()
		mockEngine.EXPECT().Register(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
		mockEngine.EXPECT().GetNetworkAccess().Return(mockNetworkAccess).AnyTimes()
		mockNetworkAccess.EXPECT().GetHttpClient().Return(httpClient).AnyTimes()
		mockNetworkAccess.EXPECT().Clone().Return(mockNetworkAccess).AnyTimes()
		mockNetworkAccess.EXPECT().SetConfiguration(gomock.Any()).AnyTimes()

		err := Init(mockEngine)
		require.NoError(t, err)
		assert.Len(t, requestedOrgs, 0, "Not expecting any requests before the first fetch")
		assert.Len(t, requestedAPIs, 0, "Not expecting any requests before the first fetch")

		// Fetch SAST settings from global config
		result1, err := config.GetWithError(ConfigurationSastSettings)
		require.NoError(t, err)
		sastResponse1, ok := result1.(*sast_contract.SastResponse)
		require.True(t, ok, "Response should be a SastResponse")
		assert.True(t, sastResponse1.SastEnabled, "Expecting globalOrg to have SAST enabled, since that is what we mocked it to be")
		assert.True(t, sastResponse1.LocalCodeEngine.Enabled, "Expecting globalAPIEndpoint to have local code engine enabled, since that is what we mocked it to be")
		assert.Equal(t, []string{globalOrg}, requestedOrgs, "First fetch should use globalOrg")
		assert.Equal(t, []string{globalAPIEndpoint}, requestedAPIs, "First fetch should use globalAPIEndpoint")

		// Clone config and change both org and API URL
		clonedConfig := config.Clone()
		clonedConfig.Set(configuration.ORGANIZATION, clonedOrg)
		clonedConfig.Set(configuration.API_URL, cloneAPIEndpoint)
		assert.Len(t, requestedOrgs, 1, "Cloning and setting values should not make requests")
		assert.Len(t, requestedAPIs, 1, "Cloning and setting values should not make requests")

		// Fetch SAST settings from cloned config
		result2, err := clonedConfig.GetWithError(ConfigurationSastSettings)
		require.NoError(t, err)
		sastResponse2, ok := result2.(*sast_contract.SastResponse)
		require.True(t, ok, "Response should be a SastResponse")
		assert.False(t, sastResponse2.SastEnabled, "Expecting clonedOrg to have SAST disabled, since that is what we mocked it to be")
		assert.False(t, sastResponse2.LocalCodeEngine.Enabled, "Expecting clonedAPIEndpoint to have local code engine disabled, since that is what we mocked it to be")
		assert.Equal(t, []string{globalOrg, clonedOrg}, requestedOrgs, "Second fetch should use clonedOrg")
		assert.Equal(t, []string{globalAPIEndpoint, cloneAPIEndpoint}, requestedAPIs, "Second fetch should use cloneAPIEndpoint")
	})
}

type boolConfigTestCase struct {
	name          string
	configKey     string
	getCallback   func(engine workflow.Engine) configuration.DefaultValueFunction
	trueResponse  *sast_contract.SastResponse
	falseResponse *sast_contract.SastResponse
	precachedMsg  string
}

func runBoolConfigTests(t *testing.T, tc boolConfigTestCase) {
	t.Helper()

	t.Run("callback function returns existing value when provided", func(t *testing.T) {
		mockEngine := setupMockEngine(t)
		result, err := tc.getCallback(mockEngine)(mockEngine.GetConfiguration(), true)
		assert.NoError(t, err)
		boolResult, ok := result.(bool)
		assert.True(t, ok, "result should be of type bool")
		assert.True(t, boolResult, "Should return existing value when provided")
	})

	t.Run("callback reads from ConfigurationSastSettings (pre-cached) when existing value is nil", func(t *testing.T) {
		mockEngine := setupMockEngine(t)
		config := mockEngine.GetConfiguration()

		config.Set(ConfigurationSastSettings, tc.trueResponse)

		result, err := tc.getCallback(mockEngine)(config, nil)
		assert.NoError(t, err)
		boolResult, ok := result.(bool)
		assert.True(t, ok, "result should be of type bool")
		assert.True(t, boolResult, tc.precachedMsg)
	})

	t.Run("depends on ConfigurationSastSettings", func(t *testing.T) {
		testutils.CheckConfigCachesDependency(
			t,
			tc.configKey,
			ConfigurationSastSettings,
			tc.getCallback,
			tc.trueResponse,
			tc.falseResponse,
			true,
			false,
		)
	})

	t.Run("respects organization changes (full chain)", func(t *testing.T) {
		testutils.CheckCacheRespectOrgDependency(
			t,
			tc.configKey,
			func(isFirstCall bool) any {
				if isFirstCall {
					return tc.trueResponse
				}
				return tc.falseResponse
			},
			Init,
			true,
			false,
		)
	})

	t.Run("callback returns false and error when API call fails and existing value is nil", func(t *testing.T) {
		server := setupMockServerWithError(t)
		defer server.Close()

		mockEngine, config := setupMockEngineWithServer(t, server)

		result, err := tc.getCallback(mockEngine)(config, nil)
		assert.Error(t, err)
		boolResult, ok := result.(bool)
		assert.True(t, ok, "result should be of type bool")
		assert.False(t, boolResult, "Should return false when API call fails")
	})
}

func Test_getSastEnabled(t *testing.T) {
	runBoolConfigTests(t, boolConfigTestCase{
		name:        "getSastEnabled",
		configKey:   ConfigurationSastEnabled,
		getCallback: getSastEnabled,
		trueResponse: &sast_contract.SastResponse{
			SastEnabled:     true,
			LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: false},
		},
		falseResponse: &sast_contract.SastResponse{
			SastEnabled:     false,
			LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: false},
		},
		precachedMsg: "Should return SastEnabled from ConfigurationSastSettings",
	})
}

func Test_getSlceEnabled(t *testing.T) {
	runBoolConfigTests(t, boolConfigTestCase{
		name:        "getSlceEnabled",
		configKey:   ConfigurationSlceEnabled,
		getCallback: getSlceEnabled,
		trueResponse: &sast_contract.SastResponse{
			SastEnabled:     false,
			LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: true},
		},
		falseResponse: &sast_contract.SastResponse{
			SastEnabled:     false,
			LocalCodeEngine: sast_contract.LocalCodeEngine{Enabled: false},
		},
		precachedMsg: "Should return LocalCodeEngine.Enabled from ConfigurationSastSettings",
	})
}
