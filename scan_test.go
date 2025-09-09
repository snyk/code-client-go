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
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	codeclient "github.com/snyk/code-client-go"
	"github.com/snyk/code-client-go/bundle"
	bundleMocks "github.com/snyk/code-client-go/bundle/mocks"
	confMocks "github.com/snyk/code-client-go/config/mocks"
	httpmocks "github.com/snyk/code-client-go/http/mocks"
	mockAnalysis "github.com/snyk/code-client-go/internal/analysis/mocks"
	"github.com/snyk/code-client-go/internal/deepcode"
	deepcodeMocks "github.com/snyk/code-client-go/internal/deepcode/mocks"
	"github.com/snyk/code-client-go/observability/mocks"
	"github.com/snyk/code-client-go/sarif"
	"github.com/snyk/code-client-go/scan"
	trackerMocks "github.com/snyk/code-client-go/scan/mocks"
)

func Test_UploadAndAnalyze(t *testing.T) {
	baseDir, firstDocPath, secondDocPath, firstDocContent, secondDocContent := setupDocs(t)
	docs := sliceToChannel([]string{firstDocPath, secondDocPath})
	firstBundle, err := deepcode.BundleFileFrom(firstDocContent, false)
	assert.NoError(t, err)
	secondBundle, err := deepcode.BundleFileFrom(secondDocContent, false)
	assert.NoError(t, err)

	files := map[string]deepcode.BundleFile{
		firstDocPath: firstBundle,
		firstDocPath: secondBundle,
	}

	logger := zerolog.Nop()

	testOrgId := uuid.NewString()

	ctrl := gomock.NewController(t)
	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().SnykCodeApi().AnyTimes().Return("")
	mockConfig.EXPECT().IsFedramp().AnyTimes().Return(false)
	mockConfig.EXPECT().Organization().AnyTimes().Return(testOrgId)
	mockConfig.EXPECT().SnykApi().AnyTimes().Return("")
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().Context().Return(t.Context()).AnyTimes()
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
	mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
	mockTrackerFactory := trackerMocks.NewMockTrackerFactory(ctrl)

	target := scan.RepositoryTarget{LocalFilePath: baseDir}

	t.Run(
		"should just create bundle when hash empty", func(t *testing.T) {
			requestId := uuid.NewString()
			mockBundle := bundle.NewBundle(deepcodeMocks.NewMockDeepcodeClient(ctrl), mockInstrumentor, mockErrorReporter, &logger, "testRootPath", "", files, []string{}, []string{})
			mockBundleManager := bundleMocks.NewMockBundleManager(ctrl)
			mockBundleManager.EXPECT().Create(gomock.Any(), requestId, baseDir, gomock.Any(), map[string]bool{}).Return(mockBundle, nil)
			mockBundleManager.EXPECT().Upload(gomock.Any(), requestId, mockBundle, files).Return(mockBundle, nil)

			codeScanner := codeclient.NewCodeScanner(
				mockConfig,
				mockHTTPClient,
				codeclient.WithTrackerFactory(mockTrackerFactory),
				codeclient.WithInstrumentor(mockInstrumentor),
				codeclient.WithErrorReporter(mockErrorReporter),
				codeclient.WithLogger(&logger),
			)

			response, bundleHash, err := codeScanner.WithBundleManager(mockBundleManager).UploadAndAnalyze(t.Context(), requestId, target, docs, map[string]bool{})
			require.NoError(t, err)
			assert.Equal(t, "", bundleHash)
			assert.Nil(t, response)
		},
	)

	t.Run(
		"should be able to upload without analysis", func(t *testing.T) {
			requestId := uuid.NewString()
			mockBundle := bundle.NewBundle(deepcodeMocks.NewMockDeepcodeClient(ctrl), mockInstrumentor, mockErrorReporter, &logger, "testRootPath", uuid.NewString(), files, []string{}, []string{})
			mockBundleManager := bundleMocks.NewMockBundleManager(ctrl)
			mockBundleManager.EXPECT().Create(gomock.Any(), requestId, baseDir, gomock.Any(), map[string]bool{}).Return(mockBundle, nil)
			mockBundleManager.EXPECT().Upload(gomock.Any(), requestId, mockBundle, files).Return(mockBundle, nil)

			codeScanner := codeclient.NewCodeScanner(
				mockConfig,
				mockHTTPClient,
				codeclient.WithTrackerFactory(mockTrackerFactory),
				codeclient.WithInstrumentor(mockInstrumentor),
				codeclient.WithErrorReporter(mockErrorReporter),
				codeclient.WithLogger(&logger),
			)

			uploadedBundle, err := codeScanner.
				WithBundleManager(mockBundleManager).
				Upload(t.Context(), requestId, target, docs, map[string]bool{})
			require.NoError(t, err)
			assert.Equal(t, mockBundle.GetBundleHash(), uploadedBundle.GetBundleHash())
		},
	)

	t.Run(
		"should retrieve from backend", func(t *testing.T) {
			requestId := uuid.NewString()
			mockBundle := bundle.NewBundle(deepcodeMocks.NewMockDeepcodeClient(ctrl), mockInstrumentor, mockErrorReporter, &logger, "testRootPath", uuid.NewString(), files, []string{}, []string{})
			mockBundleManager := bundleMocks.NewMockBundleManager(ctrl)
			mockBundleManager.EXPECT().Create(gomock.Any(), requestId, baseDir, gomock.Any(), map[string]bool{}).Return(mockBundle, nil)
			mockBundleManager.EXPECT().Upload(gomock.Any(), requestId, mockBundle, files).Return(mockBundle, nil)

			mockAnalysisOrchestrator := mockAnalysis.NewMockAnalysisOrchestrator(ctrl)
			mockAnalysisOrchestrator.EXPECT().RunTest(
				gomock.Any(),
				testOrgId,
				gomock.Any(),
				gomock.Any(),
				gomock.Any(),
			).Return(&sarif.SarifResponse{Status: "COMPLETE"}, &scan.ResultMetaData{}, nil)

			codeScanner := codeclient.NewCodeScanner(
				mockConfig,
				mockHTTPClient,
				codeclient.WithTrackerFactory(mockTrackerFactory),
				codeclient.WithInstrumentor(mockInstrumentor),
				codeclient.WithErrorReporter(mockErrorReporter),
				codeclient.WithLogger(&logger),
			)

			response, bundleHash, err := codeScanner.
				WithBundleManager(mockBundleManager).
				WithAnalysisOrchestrator(mockAnalysisOrchestrator).
				UploadAndAnalyze(t.Context(), requestId, target, docs, map[string]bool{})
			require.NoError(t, err)
			assert.Equal(t, "COMPLETE", response.Status)
			assert.Equal(t, mockBundle.GetBundleHash(), bundleHash)
		},
	)

	t.Run(
		"should send the changed files to the analysis", func(t *testing.T) {
			relativeChangedFile := "./nested/folder/nested/file.ts"
			requestId := uuid.NewString()
			mockBundle := bundle.NewBundle(deepcodeMocks.NewMockDeepcodeClient(ctrl), mockInstrumentor, mockErrorReporter, &logger, "testRootPath", uuid.NewString(), files, []string{relativeChangedFile}, []string{})
			mockBundleManager := bundleMocks.NewMockBundleManager(ctrl)
			mockBundleManager.EXPECT().Create(gomock.Any(), requestId, baseDir, gomock.Any(), map[string]bool{}).Return(mockBundle, nil)
			mockBundleManager.EXPECT().Upload(gomock.Any(), requestId, mockBundle, files).Return(mockBundle, nil)

			mockAnalysisOrchestrator := mockAnalysis.NewMockAnalysisOrchestrator(ctrl)
			mockAnalysisOrchestrator.EXPECT().RunTest(
				gomock.Any(),
				testOrgId,
				gomock.Any(),
				gomock.Any(),
				gomock.Any(),
			).Return(&sarif.SarifResponse{Status: "COMPLETE"}, &scan.ResultMetaData{}, nil)

			codeScanner := codeclient.NewCodeScanner(
				mockConfig,
				mockHTTPClient,
				codeclient.WithTrackerFactory(mockTrackerFactory),
				codeclient.WithInstrumentor(mockInstrumentor),
				codeclient.WithErrorReporter(mockErrorReporter),
				codeclient.WithLogger(&logger),
			)

			response, _, err := codeScanner.
				WithBundleManager(mockBundleManager).
				WithAnalysisOrchestrator(mockAnalysisOrchestrator).
				UploadAndAnalyze(t.Context(), requestId, target, docs, map[string]bool{})
			require.NoError(t, err)
			assert.Equal(t, "COMPLETE", response.Status)
		},
	)
}

func TestAnalyzeRemote(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().Organization().AnyTimes().Return("mockOrgId")

	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes().Return("testTraceId")
	mockSpan.EXPECT().Context().AnyTimes().Return(t.Context())
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).AnyTimes().Return(mockSpan)
	mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()

	logger := zerolog.Nop()
	mockAnalysisOrchestrator := mockAnalysis.NewMockAnalysisOrchestrator(ctrl)

	codeScanner := codeclient.NewCodeScanner(
		mockConfig,
		mockHTTPClient,
		codeclient.WithInstrumentor(mockInstrumentor),
		codeclient.WithErrorReporter(mockErrorReporter),
		codeclient.WithLogger(&logger),
	).WithAnalysisOrchestrator(mockAnalysisOrchestrator)

	t.Run("returns valid response", func(t *testing.T) {
		mockAnalysisOrchestrator.EXPECT().RunTestRemote(
			gomock.Any(),
			"mockOrgId",
			gomock.Any(),
		).Return(&sarif.SarifResponse{Status: "COMPLETE"}, &scan.ResultMetaData{}, nil)

		response, _, err := codeScanner.AnalyzeRemote(t.Context())
		if err != nil {
			t.Fatalf("AnalyzeRemote failed: %v", err)
		}
		if response == nil || response.Status != "COMPLETE" {
			t.Fatalf("expected COMPLETE, got %+v", response)
		}
	})

	t.Run("handles orchestrator error", func(t *testing.T) {
		mockAnalysisOrchestrator.EXPECT().RunTestRemote(
			gomock.Any(),
			gomock.Any(),
			gomock.Any(),
		).Return(nil, nil, assert.AnError)

		mockErrorReporter.EXPECT().CaptureError(gomock.Any(), gomock.Any())

		response, _, err := codeScanner.AnalyzeRemote(t.Context())
		assert.Nil(t, response)
		assert.Error(t, err)
	})
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
