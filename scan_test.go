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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/sourcegraph/go-lsp"
	sglsp "github.com/sourcegraph/go-lsp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.lsp.dev/uri"

	codeclient "github.com/snyk/code-client-go"
	"github.com/snyk/code-client-go/bundle"
	mocks2 "github.com/snyk/code-client-go/bundle/mocks"
	"github.com/snyk/code-client-go/deepcode"
	mocks3 "github.com/snyk/code-client-go/deepcode/mocks"
	"github.com/snyk/code-client-go/observability"
	"github.com/snyk/code-client-go/observability/mocks"
)

func Test_UploadAndAnalyze(t *testing.T) {
	baseDir, firstDoc, secondDoc, firstDocContent, secondDocContent := setupDocs(t)
	firstDocPath := pathFromUri(firstDoc.URI)
	secondDocPath := pathFromUri(secondDoc.URI)
	docs := sliceToChannel([]string{firstDocPath, secondDocPath})
	files := map[string]deepcode.BundleFile{
		firstDocPath: deepcode.BundleFileFrom(firstDocPath, firstDocContent),
		firstDocPath: deepcode.BundleFileFrom(secondDocPath, secondDocContent),
	}

	scanMetrics := observability.NewScanMetrics(time.Now(), 0)

	t.Run(
		"should create bundle when hash empty", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockSpan := mocks.NewMockSpan(ctrl)
			mockSpan.EXPECT().GetTraceId().Return("testRequestId").AnyTimes()
			mockSpan.EXPECT().Context().Return(context.Background()).AnyTimes()
			mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
			mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
			mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
			mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
			mockBundle := bundle.NewBundle(mocks3.NewMockSnykCodeClient(ctrl), mockInstrumentor, mockErrorReporter, "", "testRequestId", baseDir, files, []string{}, []string{})
			mockBundleManager := mocks2.NewMockBundleManager(ctrl)
			mockBundleManager.EXPECT().Create(gomock.Any(), "testHost", "testRequestId", baseDir, gomock.Any(), map[string]bool{}).Return(mockBundle, nil)
			mockBundleManager.EXPECT().Upload(gomock.Any(), "testHost", mockBundle, files).Return(mockBundle, nil)
			mockAnalytics := mocks.NewMockAnalytics(ctrl)

			codeScanner := codeclient.NewCodeScanner(mockBundleManager, mockInstrumentor, mockErrorReporter, mockAnalytics)

			response, bundle, err := codeScanner.UploadAndAnalyze(context.Background(), "testHost", baseDir, docs, map[string]bool{}, scanMetrics)
			require.NoError(t, err)
			assert.Equal(t, "", bundle.GetBundleHash())
			assert.Equal(t, files, bundle.GetFiles())
			assert.Nil(t, response)
		},
	)

	t.Run(
		"should retrieve from backend", func(t *testing.T) {
			ctrl := gomock.NewController(t)
			mockSpan := mocks.NewMockSpan(ctrl)
			mockSpan.EXPECT().GetTraceId().Return("testRequestId").AnyTimes()
			mockSpan.EXPECT().Context().Return(context.Background()).AnyTimes()
			mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
			mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
			mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
			mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
			mockBundle := bundle.NewBundle(mocks3.NewMockSnykCodeClient(ctrl), mockInstrumentor, mockErrorReporter, "testBundleHash", "testRequestId", baseDir, files, []string{}, []string{})
			mockBundleManager := mocks2.NewMockBundleManager(ctrl)
			mockBundleManager.EXPECT().Create(gomock.Any(), "testHost", "testRequestId", baseDir, gomock.Any(), map[string]bool{}).Return(mockBundle, nil)
			mockBundleManager.EXPECT().Upload(gomock.Any(), "testHost", mockBundle, files).Return(mockBundle, nil)
			mockAnalytics := mocks.NewMockAnalytics(ctrl)
			mockAnalytics.EXPECT().TrackScan(true, gomock.AssignableToTypeOf(observability.ScanMetrics{}))

			codeScanner := codeclient.NewCodeScanner(mockBundleManager, mockInstrumentor, mockErrorReporter, mockAnalytics)

			response, bundle, err := codeScanner.UploadAndAnalyze(context.Background(), "testHost", baseDir, docs, map[string]bool{}, scanMetrics)
			require.NoError(t, err)
			assert.Equal(t, "COMPLETE", response.Status)
			assert.Equal(t, "testBundleHash", bundle.GetBundleHash())
		},
	)
}

func setupDocs(t *testing.T) (string, lsp.TextDocumentItem, lsp.TextDocumentItem, []byte, []byte) {
	t.Helper()
	path := t.TempDir()

	content1 := []byte("test1")
	_ = os.WriteFile(path+string(os.PathSeparator)+"test1.java", content1, 0660)

	content2 := []byte("test2")
	_ = os.WriteFile(path+string(os.PathSeparator)+"test2.java", content2, 0660)

	firstDoc := lsp.TextDocumentItem{
		URI: pathToUri(filepath.Join(path, "test1.java")),
	}

	secondDoc := lsp.TextDocumentItem{
		URI: pathToUri(filepath.Join(path, "test2.java")),
	}
	return path, firstDoc, secondDoc, content1, content2
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

const fileScheme = "file://"
const eclipseWorkspaceFolderScheme = "file:"

func pathFromUri(documentURI sglsp.DocumentURI) string {
	u := string(documentURI)
	if !strings.HasPrefix(u, fileScheme) && strings.HasPrefix(u, eclipseWorkspaceFolderScheme) {
		u = strings.Replace(u, eclipseWorkspaceFolderScheme, fileScheme, 1)
	}
	return uri.New(u).Filename()
}

func pathToUri(path string) sglsp.DocumentURI {
	return sglsp.DocumentURI(uri.File(path))
}
