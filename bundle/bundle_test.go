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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/bundle"
	"github.com/snyk/code-client-go/internal/deepcode"
	deepcodeMocks "github.com/snyk/code-client-go/internal/deepcode/mocks"
	"github.com/snyk/code-client-go/observability/mocks"
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
		err := b.UploadBatch(context.Background(), "testRequestId", emptyBundle)
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

		err := b.UploadBatch(context.Background(), "testRequestId", bundleWithFiles)
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

		err := b.UploadBatch(context.Background(), "testRequestId", bundleWithFiles)
		require.NoError(t, err)
		oldHash := b.GetBundleHash()
		err = b.UploadBatch(context.Background(), "testRequestId", bundleWithMultipleFiles)
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
		mockSnykCodeClient.EXPECT().ExtendBundle(gomock.Any(), "testBundleHash", bundleFilePartialMatcher{expectedKey: "hello", expectedContent: "world"}, []string{}).Return("newBundleHash", []string{}, nil).Times(1)

		mockSpan := mocks.NewMockSpan(ctrl)
		mockSpan.EXPECT().Context().AnyTimes()
		mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
		mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
		mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
		mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
		b := bundle.NewBundle(mockSnykCodeClient, mockInstrumentor, mockErrorReporter, &testLogger, "testRootPath", "testBundleHash", map[string]deepcode.BundleFile{}, []string{}, []string{})

		require.NoError(t, batchErr)
		oldHash := b.GetBundleHash()
		err := b.UploadBatch(context.Background(), "testRequestId", bundleFromRawContent)
		require.NoError(t, err)
		newHash := b.GetBundleHash()
		assert.NotEqual(t, oldHash, newHash)
	})
}

func Test_BundleEncoding(t *testing.T) {
	t.Run("utf-8 encoded content", func(t *testing.T) {
		content := []byte("hello")
		bundle, err := deepcode.BundleFileFrom(content)
		assert.NoError(t, err)

		actualShasum := sha256.Sum256([]byte(bundle.Content))
		assert.Equal(t, bundle.Hash, hex.EncodeToString(actualShasum[:]))
	})

	t.Run("non utf-8 / binary file", func(t *testing.T) {
		content, err := os.ReadFile("testdata/rshell_font.php")
		assert.NoError(t, err)

		bundle, err := deepcode.BundleFileFrom(content)
		assert.NoError(t, err)

		actualShasum := sha256.Sum256([]byte(bundle.Content))
		assert.Equal(t, bundle.Hash, hex.EncodeToString(actualShasum[:]))
	})
}
