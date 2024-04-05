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
package codeclient_test

import (
	"context"
	"github.com/snyk/code-client-go/internal/bundle"
	bundleMocks "github.com/snyk/code-client-go/internal/bundle/mocks"
	"os"
	"path/filepath"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	codeclient "github.com/snyk/code-client-go"
	confMocks "github.com/snyk/code-client-go/config/mocks"
	"github.com/snyk/code-client-go/deepcode"
	deepcodeMocks "github.com/snyk/code-client-go/deepcode/mocks"
	httpmocks "github.com/snyk/code-client-go/http/mocks"
	"github.com/snyk/code-client-go/observability/mocks"
)

func Test_UploadAndAnalyze(t *testing.T) {
	baseDir, firstDocPath, secondDocPath, firstDocContent, secondDocContent := setupDocs(t)
	docs := sliceToChannel([]string{firstDocPath, secondDocPath})
	files := map[string]deepcode.BundleFile{
		firstDocPath: deepcode.BundleFileFrom(firstDocPath, firstDocContent),
		firstDocPath: deepcode.BundleFileFrom(secondDocPath, secondDocContent),
	}

	logger := zerolog.Nop()

	ctrl := gomock.NewController(t)
	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().SnykCodeApi().AnyTimes().Return("")
	mockConfig.EXPECT().IsFedramp().AnyTimes().Return(false)
	mockConfig.EXPECT().Organization().AnyTimes().Return("")
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().Return("testRequestId").AnyTimes()
	mockSpan.EXPECT().Context().Return(context.Background()).AnyTimes()
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
	mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

	t.Run(
		"should create bundle when hash empty", func(t *testing.T) {
			mockBundle := bundle.NewBundle(deepcodeMocks.NewMockSnykCodeClient(ctrl), mockInstrumentor, mockErrorReporter, &logger, "", files, []string{}, []string{})
			mockBundleManager := bundleMocks.NewMockBundleManager(ctrl)
			mockBundleManager.EXPECT().Create(gomock.Any(), "testRequestId", baseDir, gomock.Any(), map[string]bool{}).Return(mockBundle, nil)
			mockBundleManager.EXPECT().Upload(gomock.Any(), "testRequestId", mockBundle, files).Return(mockBundle, nil)

			codeScanner := codeclient.NewCodeScanner(mockHTTPClient, mockConfig, mockInstrumentor, mockErrorReporter, &logger)

			response, bundleHash, err := codeScanner.WithBundleManager(mockBundleManager).UploadAndAnalyze(context.Background(), "testRequestId", baseDir, docs, map[string]bool{})
			require.NoError(t, err)
			assert.Equal(t, "", bundleHash)
			assert.Nil(t, response)
		},
	)

	t.Run(
		"should retrieve from backend", func(t *testing.T) {
			mockBundle := bundle.NewBundle(deepcodeMocks.NewMockSnykCodeClient(ctrl), mockInstrumentor, mockErrorReporter, &logger, "testBundleHash", files, []string{}, []string{})
			mockBundleManager := bundleMocks.NewMockBundleManager(ctrl)
			mockBundleManager.EXPECT().Create(gomock.Any(), "testRequestId", baseDir, gomock.Any(), map[string]bool{}).Return(mockBundle, nil)
			mockBundleManager.EXPECT().Upload(gomock.Any(), "testRequestId", mockBundle, files).Return(mockBundle, nil)

			codeScanner := codeclient.NewCodeScanner(mockHTTPClient, mockConfig, mockInstrumentor, mockErrorReporter, &logger)

			response, bundleHash, err := codeScanner.WithBundleManager(mockBundleManager).UploadAndAnalyze(context.Background(), "testRequestId", baseDir, docs, map[string]bool{})
			require.NoError(t, err)
			assert.Equal(t, "COMPLETE", response.Status)
			assert.Equal(t, "testBundleHash", bundleHash)
		},
	)
}

func setupDocs(t *testing.T) (string, string, string, []byte, []byte) {
	t.Helper()
	path := t.TempDir()

	content1 := []byte("test1")
	_ = os.WriteFile(path+string(os.PathSeparator)+"test1.java", content1, 0660)

	content2 := []byte("test2")
	_ = os.WriteFile(path+string(os.PathSeparator)+"test2.java", content2, 0660)

	firstDocPath := filepath.Join(path, "test1.java")
	secondDocPath := filepath.Join(path, "test2.java")
	return path, firstDocPath, secondDocPath, content1, content2
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
