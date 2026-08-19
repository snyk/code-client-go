/*
 * © 2024 Snyk Limited All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package supportedfiles_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/snyk/go-application-framework/pkg/analytics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/internal/deepcode"
	deepcodeMocks "github.com/snyk/code-client-go/internal/deepcode/mocks"
	"github.com/snyk/code-client-go/internal/util/supportedfiles"
)

func Test_IsFileSupported_Extensions(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSnykCodeClient := deepcodeMocks.NewMockDeepcodeClient(ctrl)
	mockSnykCodeClient.EXPECT().GetFilters(gomock.Any()).Return(deepcode.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".java"},
	}, nil)

	filter := supportedfiles.NewSupportedFilesFilter(mockSnykCodeClient, newLogger(t), analytics.New())
	dir := t.TempDir()

	t.Run("should return true for supported languages", func(t *testing.T) {
		supported, _ := filter.IsFileSupported(t.Context(), createFile(t, dir, "Test.java"))
		assert.True(t, supported)
	})

	t.Run("should return false for unsupported languages", func(t *testing.T) {
		supported, _ := filter.IsFileSupported(t.Context(), createFile(t, dir, "Test.rs"))
		assert.False(t, supported)
	})
}

func Test_IsFileSupported_ConfigFiles(t *testing.T) {
	configFilesFromFiltersEndpoint := []string{
		".supportedConfigFile",
		".snyk",
		".dcignore",
		".gitignore",
	}
	expectedConfigFiles := []string{ // .dcignore and .gitignore should be excluded
		".supportedConfigFile",
		".snyk",
	}

	ctrl := gomock.NewController(t)
	mockSnykCodeClient := deepcodeMocks.NewMockDeepcodeClient(ctrl)
	getFiltersCalls := 0
	mockSnykCodeClient.EXPECT().GetFilters(gomock.Any()).DoAndReturn(func(context.Context) (deepcode.FiltersResponse, error) {
		getFiltersCalls++
		return deepcode.FiltersResponse{
			ConfigFiles: configFilesFromFiltersEndpoint,
			Extensions:  []string{},
		}, nil
	})

	filter := supportedfiles.NewSupportedFilesFilter(mockSnykCodeClient, newLogger(t), analytics.New())
	dir := t.TempDir()

	t.Run("should return true for supported config files", func(t *testing.T) {
		for _, file := range expectedConfigFiles {
			supported, _ := filter.IsFileSupported(t.Context(), createFile(t, dir, file))
			assert.True(t, supported)
		}
	})
	t.Run("should exclude .gitignore and .dcignore", func(t *testing.T) {
		for _, file := range []string{".gitignore", ".dcignore"} {
			supported, _ := filter.IsFileSupported(t.Context(), createFile(t, dir, file))
			assert.False(t, supported)
		}
	})
	t.Run("should return false for unsupported config files", func(t *testing.T) {
		supported, _ := filter.IsFileSupported(t.Context(), createFile(t, dir, ".unsupported"))
		assert.False(t, supported)
	})
}

func Test_IsFileSupported_FileSize(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSnykCodeClient := deepcodeMocks.NewMockDeepcodeClient(ctrl)
	mockSnykCodeClient.EXPECT().GetFilters(gomock.Any()).Return(deepcode.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".java"},
	}, nil)

	filter := supportedfiles.NewSupportedFilesFilter(mockSnykCodeClient, newLogger(t), analytics.New())
	dir := t.TempDir()

	t.Run("should return false for empty files", func(t *testing.T) {
		path := filepath.Join(dir, "empty.java")
		require.NoError(t, os.WriteFile(path, []byte{}, 0600))
		supported, _ := filter.IsFileSupported(t.Context(), path)
		assert.False(t, supported)
	})

	t.Run("should return false for files over the max size", func(t *testing.T) {
		path := filepath.Join(dir, "big.java")
		require.NoError(t, os.WriteFile(path, make([]byte, 1024*1024+1), 0600))
		supported, _ := filter.IsFileSupported(t.Context(), path)
		assert.False(t, supported)
	})
}

func Test_IsFileSupported_Analytics(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSnykCodeClient := deepcodeMocks.NewMockDeepcodeClient(ctrl)
	mockSnykCodeClient.EXPECT().GetFilters(gomock.Any()).Return(deepcode.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".java"},
	}, nil)

	recorder := newRecordingAnalytics()
	filter := supportedfiles.NewSupportedFilesFilter(mockSnykCodeClient, newLogger(t), recorder)
	dir := t.TempDir()

	for _, name := range []string{"A.java", "B.java", "C.java"} {
		supported, err := filter.IsFileSupported(t.Context(), createFile(t, dir, name))
		require.NoError(t, err)
		require.True(t, supported)
	}

	t.Run("should report the GetFilters API duration", func(t *testing.T) {
		// The duration itself is not asserted: the client is mocked, so it rounds to 0ms.
		assert.Contains(t, recorder.extensionValues, "get_filters_ms")
	})

	t.Run("should fetch the filters once for the whole scan", func(t *testing.T) {
		assert.Equal(t, 1, recorder.extensionValues["get_filters_calls"])
	})
}

func createFile(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("some content so the file won't be skipped"), 0600))
	return path
}

func newLogger(t *testing.T) *zerolog.Logger {
	t.Helper()
	logger := zerolog.New(zerolog.NewTestWriter(t))
	return &logger
}

// recordingAnalytics captures the reported extension values. GAF provides no mock for
// analytics.Analytics, and its collector offers no way to read recorded values back, so the
// real implementation is embedded and the one method under test is shadowed.
type recordingAnalytics struct {
	analytics.Analytics
	extensionValues map[string]int
}

func newRecordingAnalytics() *recordingAnalytics {
	return &recordingAnalytics{
		Analytics:       analytics.New(),
		extensionValues: map[string]int{},
	}
}

func (r *recordingAnalytics) AddExtensionIntegerValue(key string, value int) {
	r.extensionValues[key] = value
}
