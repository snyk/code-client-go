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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"testing"

	"golang.org/x/net/html/charset"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"

	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/internal/deepcode"
	deepcodeMocks "github.com/snyk/code-client-go/internal/deepcode/mocks"
	"github.com/snyk/code-client-go/internal/util"
	"github.com/snyk/code-client-go/observability/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var bundleWithFiles = bundle.NewBatch(map[string]deepcode.BundleFile{"file": {}})
var bundleWithMultipleFiles = bundle.NewBatch(map[string]deepcode.BundleFile{
	"file":    {},
	"another": {},
})
var bundleFromRawContent, batchErr = bundle.NewBatchFromRawContent(map[string][]byte{"hello": []byte("world")})

// Matcher for BundleFile that matches on key and content (ignores hash)
type bundleFilePartialMatcher struct {
	expectedKey     string
	expectedContent string
}

func (m bundleFilePartialMatcher) Matches(x interface{}) bool {
	files, ok := x.(map[string]deepcode.BundleFile)
	if !ok {
		return false
	}
	file, exists := files[m.expectedKey]
	if !exists {
		return false
	}
	return file.Content == m.expectedContent
}

func (m bundleFilePartialMatcher) String() string {
	return fmt.Sprintf("{ Key : '%s', Content : '%s' }", m.expectedKey, m.expectedContent)
}

func Test_UploadBatch(t *testing.T) {
	testLogger := zerolog.Nop()

	t.Run("when no documents - creates nothing", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockSnykCodeClient := deepcodeMocks.NewMockDeepcodeClient(ctrl)

		mockSpan := mocks.NewMockSpan(ctrl)
		mockSpan.EXPECT().Context().AnyTimes()
		mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
		mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
		mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
		mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
		b := bundle.NewBundle(mockSnykCodeClient, mockInstrumentor, mockErrorReporter, &testLogger, "testRootPath", "testBundleHash", map[string]deepcode.BundleFile{}, []string{}, []string{})

		emptyBundle := &bundle.Batch{}
		err := b.UploadBatch(t.Context(), "testRequestId", emptyBundle)
		assert.NoError(t, err)
	})

	t.Run("when no bundles - creates new deepCodeBundle and sets hash", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockSnykCodeClient := deepcodeMocks.NewMockDeepcodeClient(ctrl)
		mockSnykCodeClient.EXPECT().ExtendBundle(gomock.Any(), "testBundleHash", map[string]deepcode.BundleFile{
			"file": {},
		}, []string{}).Return("testBundleHash", []string{}, nil)

		mockSpan := mocks.NewMockSpan(ctrl)
		mockSpan.EXPECT().Context().AnyTimes()
		mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
		mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
		mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
		mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
		b := bundle.NewBundle(mockSnykCodeClient, mockInstrumentor, mockErrorReporter, &testLogger, "testRootPath", "testBundleHash", map[string]deepcode.BundleFile{}, []string{}, []string{})

		err := b.UploadBatch(t.Context(), "testRequestId", bundleWithFiles)
		assert.NoError(t, err)
	})

	t.Run("when existing bundles - extends deepCodeBundle and updates hash", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockSnykCodeClient := deepcodeMocks.NewMockDeepcodeClient(ctrl)
		mockSnykCodeClient.EXPECT().ExtendBundle(gomock.Any(), "testBundleHash", map[string]deepcode.BundleFile{
			"another": {},
			"file":    {},
		}, []string{}).Return("bundleWithMultipleFilesHash", []string{}, nil).Times(1)
		mockSnykCodeClient.EXPECT().ExtendBundle(gomock.Any(), "testBundleHash", map[string]deepcode.BundleFile{
			"file": {},
		}, []string{}).Return("testBundleHash", []string{}, nil).Times(1)

		mockSpan := mocks.NewMockSpan(ctrl)
		mockSpan.EXPECT().Context().AnyTimes()
		mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
		mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
		mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
		mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
		b := bundle.NewBundle(mockSnykCodeClient, mockInstrumentor, mockErrorReporter, &testLogger, "testRootPath", "testBundleHash", map[string]deepcode.BundleFile{}, []string{}, []string{})

		err := b.UploadBatch(t.Context(), "testRequestId", bundleWithFiles)
		require.NoError(t, err)
		oldHash := b.GetBundleHash()
		err = b.UploadBatch(t.Context(), "testRequestId", bundleWithMultipleFiles)
		require.NoError(t, err)
		newHash := b.GetBundleHash()
		assert.NotEqual(t, oldHash, newHash)
	})
}

func Test_RawContentBatch(t *testing.T) {
	testLogger := zerolog.Nop()

	t.Run("create a batch from raw content and upload the bundle", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockSnykCodeClient := deepcodeMocks.NewMockDeepcodeClient(ctrl)
		mockSnykCodeClient.EXPECT().ExtendBundle(gomock.Any(), "testBundleHash", bundleFilePartialMatcher{expectedKey: "hello", expectedContent: ""}, []string{}).Return("newBundleHash", []string{}, nil).Times(1)

		mockSpan := mocks.NewMockSpan(ctrl)
		mockSpan.EXPECT().Context().AnyTimes()
		mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
		mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
		mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
		mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
		b := bundle.NewBundle(mockSnykCodeClient, mockInstrumentor, mockErrorReporter, &testLogger, "testRootPath", "testBundleHash", map[string]deepcode.BundleFile{}, []string{}, []string{})

		require.NoError(t, batchErr)
		oldHash := b.GetBundleHash()
		err := b.UploadBatch(t.Context(), "testRequestId", bundleFromRawContent)
		require.NoError(t, err)
		newHash := b.GetBundleHash()
		assert.NotEqual(t, oldHash, newHash)
	})
}

func Test_BundleEncoding(t *testing.T) {
	t.Run("utf-8 encoded content", func(t *testing.T) {
		content := []byte("hello")
		bundleFile, err := deepcode.BundleFileFrom(content, false)
		assert.NoError(t, err)

		ExpectedShaSum := sha256.Sum256(content)
		assert.Equal(t, hex.EncodeToString(ExpectedShaSum[:]), bundleFile.Hash)
	})

	t.Run("non utf-8 / binary file", func(t *testing.T) {
		content, err := os.ReadFile("testdata/rshell_font.php")
		assert.NoError(t, err)

		bundleFile, err := deepcode.BundleFileFrom(content, false)
		assert.NoError(t, err)

		byteReader := bytes.NewReader(content)
		reader, _ := charset.NewReaderLabel("UTF-8", byteReader)
		utf8content, _ := io.ReadAll(reader)
		ExpectedShaSum := sha256.Sum256(utf8content)
		assert.Equal(t, hex.EncodeToString(ExpectedShaSum[:]), bundleFile.Hash)
	})
}

func Test_BundleFileContent(t *testing.T) {
	t.Run("include file contents", func(t *testing.T) {
		content := []byte("hello")
		bundleFile, err := deepcode.BundleFileFrom(content, true)
		assert.NoError(t, err)

		utf8Content, err := util.ConvertToUTF8(content)
		assert.NoError(t, err)

		assert.Equal(t, string(utf8Content), bundleFile.Content)
		assert.Equal(t, len(content), bundleFile.ContentSize)
	})

	t.Run("exclude file contents", func(t *testing.T) {
		content := []byte("hello")
		bundleFile, err := deepcode.BundleFileFrom(content, false)
		assert.NoError(t, err)

		assert.Equal(t, "", bundleFile.Content)
		// Note that we still expect the bundle to indicate the expected final size.
		assert.Equal(t, len(content), bundleFile.ContentSize)
	})
}
