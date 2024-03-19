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

package bundle_test

import (
	"bytes"
	"context"
	"github.com/rs/zerolog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/bundle"
	deepcode2 "github.com/snyk/code-client-go/deepcode"
	mocks2 "github.com/snyk/code-client-go/deepcode/mocks"
	"github.com/snyk/code-client-go/internal/util"
	"github.com/snyk/code-client-go/observability/mocks"
)

func Test_Create(t *testing.T) {
	t.Run(
		"when < maxFileSize creates deepCodeBundle", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockSpan := mocks.NewMockSpan(ctrl)
			mockSpan.EXPECT().Context().AnyTimes()
			mockSnykCodeClient := mocks2.NewMockSnykCodeClient(ctrl)
			mockSnykCodeClient.EXPECT().GetFilters(gomock.Any(), "testHost").Return(deepcode2.FiltersResponse{
				ConfigFiles: []string{},
				Extensions:  []string{".java"},
			}, nil)
			mockSnykCodeClient.EXPECT().CreateBundle(gomock.Any(), "testHost", map[string]string{
				"file.java": "386f1997f6da5133a0f75c347d5cdff15a428b817231278e2509832c1a80b3ea",
			}).Times(1)
			mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
			mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
			mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
			mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

			dir := t.TempDir()
			file := filepath.Join(dir, "file.java")
			data := strings.Repeat("a", 1024*1024-10)
			err := os.WriteFile(file, []byte(data), 0600)
			require.NoError(t, err)

			var bundleManager = bundle.NewBundleManager(workflow.NewDefaultWorkFlowEngine(), mockSnykCodeClient, mockInstrumentor, mockErrorReporter)
			bundle, err := bundleManager.Create(context.Background(),
				"testHost",
				"testRequestId",
				dir,
				sliceToChannel([]string{file}),
				map[string]bool{})
			require.NoError(t, err)
			assert.Len(t, bundle.GetFiles(), 1, "deepCodeBundle should have 1 deepCodeBundle files")
		},
	)

	t.Run(
		"when too big ignores file", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockSpan := mocks.NewMockSpan(ctrl)
			mockSpan.EXPECT().Context().AnyTimes()
			mockSnykCodeClient := mocks2.NewMockSnykCodeClient(ctrl)
			mockSnykCodeClient.EXPECT().GetFilters(gomock.Any(), "testHost").Return(deepcode2.FiltersResponse{
				ConfigFiles: []string{},
				Extensions:  []string{".java"},
			}, nil)
			mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
			mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
			mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
			mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

			dir := t.TempDir()
			file := filepath.Join(dir, "file.java")
			data := strings.Repeat("a", 1024*1024+1)
			err := os.WriteFile(file, []byte(data), 0600)
			require.NoError(t, err)

			var bundleManager = bundle.NewBundleManager(workflow.NewDefaultWorkFlowEngine(), mockSnykCodeClient, mockInstrumentor, mockErrorReporter)
			bundle, err := bundleManager.Create(context.Background(),
				"testHost",
				"testRequestId",
				dir,
				sliceToChannel([]string{file}),
				map[string]bool{})
			require.NoError(t, err)
			assert.Len(t, bundle.GetFiles(), 0, "deepCodeBundle should not have deepCodeBundle files")
		},
	)

	//nolint:dupl // test cases differ by a boolean
	t.Run(
		"when empty file ignores file", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockSpan := mocks.NewMockSpan(ctrl)
			mockSpan.EXPECT().Context().AnyTimes()
			mockSnykCodeClient := mocks2.NewMockSnykCodeClient(ctrl)
			mockSnykCodeClient.EXPECT().GetFilters(gomock.Any(), "testHost").Return(deepcode2.FiltersResponse{
				ConfigFiles: []string{},
				Extensions:  []string{".java"},
			}, nil)
			mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
			mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
			mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
			mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

			dir := t.TempDir()
			file := filepath.Join(dir, "file.java")
			fd, err := os.Create(file)
			t.Cleanup(
				func() {
					_ = fd.Close()
				},
			)
			require.NoError(t, err)

			var bundleManager = bundle.NewBundleManager(workflow.NewDefaultWorkFlowEngine(), mockSnykCodeClient, mockInstrumentor, mockErrorReporter)
			bundle, err := bundleManager.Create(context.Background(),
				"testHost",
				"testRequestId",
				dir,
				sliceToChannel([]string{file}),
				map[string]bool{})
			require.NoError(t, err)
			assert.Len(t, bundle.GetFiles(), 0, "deepCodeBundle should not have deepCodeBundle files")
		},
	)

	//nolint:dupl // test cases differ by the extension of the file
	t.Run(
		"when unsupported ignores file", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockSpan := mocks.NewMockSpan(ctrl)
			mockSpan.EXPECT().Context().AnyTimes()
			mockSnykCodeClient := mocks2.NewMockSnykCodeClient(ctrl)
			mockSnykCodeClient.EXPECT().GetFilters(gomock.Any(), "testHost").Return(deepcode2.FiltersResponse{
				ConfigFiles: []string{},
				Extensions:  []string{".java"},
			}, nil)
			mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
			mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
			mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
			mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

			dir := t.TempDir()
			file := filepath.Join(dir, "file.rb")
			fd, err := os.Create(file)
			t.Cleanup(
				func() {
					_ = fd.Close()
				},
			)
			require.NoError(t, err)
			var bundleManager = bundle.NewBundleManager(workflow.NewDefaultWorkFlowEngine(), mockSnykCodeClient, mockInstrumentor, mockErrorReporter)
			bundle, err := bundleManager.Create(context.Background(),
				"testHost",
				"testRequestId",
				dir,
				sliceToChannel([]string{file}),
				map[string]bool{})
			require.NoError(t, err)
			assert.Len(t, bundle.GetFiles(), 0, "deepCodeBundle should not have deepCodeBundle files")
		},
	)

	t.Run("includes config files", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockSpan := mocks.NewMockSpan(ctrl)
		mockSpan.EXPECT().Context().AnyTimes()
		mockSnykCodeClient := mocks2.NewMockSnykCodeClient(ctrl)
		mockSnykCodeClient.EXPECT().GetFilters(gomock.Any(), "testHost").Return(deepcode2.FiltersResponse{
			ConfigFiles: []string{".test"},
			Extensions:  []string{},
		}, nil)
		mockSnykCodeClient.EXPECT().CreateBundle(gomock.Any(), "testHost", map[string]string{
			".test": "9c05690c5b8e22df259431c95df33d01267f799de6810382ada1a9ff1b89710e",
		}).Times(1)
		mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
		mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
		mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
		mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

		tempDir := t.TempDir()
		file := filepath.Join(tempDir, ".test")
		err := os.WriteFile(file, []byte("some content so the file won't be skipped"), 0600)
		assert.Nil(t, err)

		var bundleManager = bundle.NewBundleManager(workflow.NewDefaultWorkFlowEngine(), mockSnykCodeClient, mockInstrumentor, mockErrorReporter)
		bundle, err := bundleManager.Create(context.Background(),
			"testHost",
			"testRequestId",
			tempDir,
			sliceToChannel([]string{file}),
			map[string]bool{})
		require.NoError(t, err)
		relativePath, _ := util.ToRelativeUnixPath(tempDir, file)
		assert.Contains(t, bundle.GetFiles(), relativePath)
	})

	t.Run("url-encodes files", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockSpan := mocks.NewMockSpan(ctrl)
		mockSpan.EXPECT().Context().AnyTimes()
		mockSnykCodeClient := mocks2.NewMockSnykCodeClient(ctrl)
		mockSnykCodeClient.EXPECT().GetFilters(gomock.Any(), "testHost").Return(deepcode2.FiltersResponse{
			ConfigFiles: []string{},
			Extensions:  []string{".java"},
		}, nil)
		mockSnykCodeClient.EXPECT().CreateBundle(gomock.Any(), "testHost", map[string]string{
			"path/to/file1.java":            "9c05690c5b8e22df259431c95df33d01267f799de6810382ada1a9ff1b89710e",
			"path/with%20spaces/file2.java": "9c05690c5b8e22df259431c95df33d01267f799de6810382ada1a9ff1b89710e",
		}).Times(1)
		mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
		mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
		mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
		mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

		filesRelPaths := []string{
			"path/to/file1.java",
			"path/with spaces/file2.java",
		}
		expectedPaths := []string{
			"path/to/file1.java",
			"path/with%20spaces/file2.java",
		}

		tempDir := t.TempDir()
		var filesFullPaths []string
		for _, fileRelPath := range filesRelPaths {
			file := filepath.Join(tempDir, fileRelPath)
			filesFullPaths = append(filesFullPaths, file)
			_ = os.MkdirAll(filepath.Dir(file), 0700)
			err := os.WriteFile(file, []byte("some content so the file won't be skipped"), 0600)
			require.NoError(t, err)
		}

		var bundleManager = bundle.NewBundleManager(workflow.NewDefaultWorkFlowEngine(), mockSnykCodeClient, mockInstrumentor, mockErrorReporter)
		bundle, err := bundleManager.Create(context.Background(),
			"testHost",
			"testRequestId",
			tempDir,
			sliceToChannel(filesFullPaths),
			map[string]bool{})
		require.NoError(t, err)
		for _, expectedPath := range expectedPaths {
			assert.Contains(t, bundle.GetFiles(), expectedPath)
		}
	})
}

func Test_Upload(t *testing.T) {
	temporaryDir := setup(t)
	t.Cleanup(func() {
		_ = os.RemoveAll(temporaryDir)
	})

	logger := zerolog.Nop()

	t.Run("adds files to deepCodeBundle", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockSpan := mocks.NewMockSpan(ctrl)
		mockSpan.EXPECT().Context().AnyTimes()
		mockSnykCodeClient := mocks2.NewMockSnykCodeClient(ctrl)
		mockSnykCodeClient.EXPECT().ExtendBundle(gomock.Any(), "testHost", "bundleHash", gomock.Len(1), []string{}).Times(1)
		mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
		mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).Times(2)
		mockInstrumentor.EXPECT().Finish(gomock.Any()).Times(2)
		mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

		var bundleManager = bundle.NewBundleManager(workflow.NewDefaultWorkFlowEngine(), mockSnykCodeClient, mockInstrumentor, mockErrorReporter)
		documentURI, bundleFile := createTempFileInDir(t, "bundleDoc.java", 10, temporaryDir)
		bundleFileMap := map[string]deepcode2.BundleFile{}
		bundleFileMap[documentURI] = bundleFile

		_, err := bundleManager.Upload(context.Background(),
			"testHost",
			bundle.NewBundle(mockSnykCodeClient, mockInstrumentor, mockErrorReporter, &logger, "bundleHash", "testRequestId", "", bundleFileMap, []string{}, []string{documentURI}),
			bundleFileMap)
		assert.NoError(t, err)
	})

	t.Run("when loads of files breaks down in 4MB bundles", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockSpan := mocks.NewMockSpan(ctrl)
		mockSpan.EXPECT().Context().AnyTimes()
		mockSnykCodeClient := mocks2.NewMockSnykCodeClient(ctrl)
		mockSnykCodeClient.EXPECT().ExtendBundle(gomock.Any(), "testHost", "bundleHash", gomock.Len(3), []string{}).Return("newBundleHash", []string{}, nil).Times(1)
		mockSnykCodeClient.EXPECT().ExtendBundle(gomock.Any(), "testHost", "newBundleHash", gomock.Len(2), []string{}).Return("newerBundleHash", []string{}, nil).Times(1)
		mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
		mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).Times(2)
		mockInstrumentor.EXPECT().Finish(gomock.Any()).Times(2)
		mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
		var bundleManager = bundle.NewBundleManager(workflow.NewDefaultWorkFlowEngine(), mockSnykCodeClient, mockInstrumentor, mockErrorReporter)

		bundleFileMap := map[string]deepcode2.BundleFile{}
		var missingFiles []string
		path, bundleFile := createTempFileInDir(t, "bundleDoc1.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir(t, "bundleDoc2.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir(t, "bundleDoc3.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir(t, "bundleDoc4.java", (1024*1024)-1, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)
		path, bundleFile = createTempFileInDir(t, "bundleDoc5.java", 100, temporaryDir)
		bundleFileMap[path] = bundleFile
		missingFiles = append(missingFiles, path)

		_, err := bundleManager.Upload(context.Background(),
			"testHost",
			bundle.NewBundle(mockSnykCodeClient, mockInstrumentor, mockErrorReporter, &logger, "bundleHash", "testRequestId", "", bundleFileMap, []string{}, missingFiles),
			bundleFileMap)
		assert.Nil(t, err)
	})
}

func createTempFileInDir(t *testing.T, name string, size int, temporaryDir string) (string, deepcode2.BundleFile) {
	t.Helper()

	documentURI, fileContent := createFileOfSize(t, name, size, temporaryDir)
	return documentURI, deepcode2.BundleFile{Hash: util.Hash(fileContent), Content: string(fileContent)}
}

func Test_IsSupported_Extensions(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSnykCodeClient := mocks2.NewMockSnykCodeClient(ctrl)
	mockSnykCodeClient.EXPECT().GetFilters(gomock.Any(), "testHost").Return(deepcode2.FiltersResponse{
		ConfigFiles: []string{},
		Extensions:  []string{".java"},
	}, nil)
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
	bundler := bundle.NewBundleManager(workflow.NewDefaultWorkFlowEngine(), mockSnykCodeClient, mockInstrumentor, mockErrorReporter)

	t.Run("should return true for supported languages", func(t *testing.T) {
		supported, _ := bundler.IsSupported(context.Background(), "testHost", "C:\\some\\path\\Test.java")
		assert.True(t, supported)
	})

	t.Run("should return false for unsupported languages", func(t *testing.T) {
		supported, _ := bundler.IsSupported(context.Background(), "testHost", "C:\\some\\path\\Test.rs")
		assert.False(t, supported)
	})

	t.Run("should cache supported extensions", func(t *testing.T) {
		path := "C:\\some\\path\\Test.rs"
		_, _ = bundler.IsSupported(context.Background(), "testHost", path)
		_, _ = bundler.IsSupported(context.Background(), "testHost", path)
	})
}

func Test_IsSupported_ConfigFiles(t *testing.T) {
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
	mockSnykCodeClient := mocks2.NewMockSnykCodeClient(ctrl)
	mockSnykCodeClient.EXPECT().GetFilters(gomock.Any(), "testHost").Return(deepcode2.FiltersResponse{
		ConfigFiles: configFilesFromFiltersEndpoint,
		Extensions:  []string{},
	}, nil)
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
	bundler := bundle.NewBundleManager(workflow.NewDefaultWorkFlowEngine(), mockSnykCodeClient, mockInstrumentor, mockErrorReporter)
	dir, _ := os.Getwd()

	t.Run("should return true for supported config files", func(t *testing.T) {
		for _, file := range expectedConfigFiles {
			path := filepath.Join(dir, file)
			supported, _ := bundler.IsSupported(context.Background(), "testHost", path)
			assert.True(t, supported)
		}
	})
	t.Run("should exclude .gitignore and .dcignore", func(t *testing.T) {
		for _, file := range []string{".gitignore", ".dcignore"} {
			path := filepath.Join(dir, file)
			supported, _ := bundler.IsSupported(context.Background(), "testHost", path)
			assert.False(t, supported)
		}
	})
	t.Run("should return false for unsupported config files", func(t *testing.T) {
		path := "C:\\some\\path\\.unsupported"
		supported, _ := bundler.IsSupported(context.Background(), "testHost", path)
		assert.False(t, supported)
	})

	t.Run("should cache supported extensions", func(t *testing.T) {
		path := "C:\\some\\path\\Test.rs"
		_, _ = bundler.IsSupported(context.Background(), "testHost", path)
		_, _ = bundler.IsSupported(context.Background(), "testHost", path)
	})
}

func setup(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "createFileOfSize")
	require.NoError(t, err)
	return dir
}

func createFileOfSize(t *testing.T, filename string, contentSize int, dir string) (string, []byte) {
	t.Helper()

	buf := new(bytes.Buffer)
	buf.Grow(contentSize)
	for i := 0; i < contentSize; i++ {
		buf.WriteByte('a')
	}

	filePath := dir + string(os.PathSeparator) + filename
	err := os.WriteFile(filePath, buf.Bytes(), 0660)
	if err != nil {
		t.Fatal(err, "Couldn't write test file")
	}
	return filePath, buf.Bytes()
}

func sliceToChannel(slice []string) <-chan string {
	ch := make(chan string)
	go func() {
		defer close(ch)
		for _, s := range slice {
			ch <- s
		}
	}()

	return ch
}
