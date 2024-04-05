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
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/snyk/code-client-go/internal/bundle"
	"github.com/snyk/code-client-go/internal/deepcode"
	deepcodeMocks "github.com/snyk/code-client-go/internal/deepcode/mocks"
	"github.com/snyk/code-client-go/observability/mocks"
)

var bundleWithFiles = bundle.NewBatch(map[string]deepcode.BundleFile{"file": {}})
var bundleWithMultipleFiles = bundle.NewBatch(map[string]deepcode.BundleFile{
	"file":    {},
	"another": {},
})

func Test_UploadBatch(t *testing.T) {
	testLogger := zerolog.Nop()

	t.Run("when no documents - creates nothing", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockSnykCodeClient := deepcodeMocks.NewMockSnykCodeClient(ctrl)

		mockSpan := mocks.NewMockSpan(ctrl)
		mockSpan.EXPECT().Context().AnyTimes()
		mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
		mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
		mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
		mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
		b := bundle.NewBundle(mockSnykCodeClient, mockInstrumentor, mockErrorReporter, &testLogger, "", map[string]deepcode.BundleFile{}, []string{}, []string{})

		emptyBundle := &bundle.Batch{}
		err := b.UploadBatch(context.Background(), "testRequestId", emptyBundle)
		assert.NoError(t, err)
	})

	t.Run("when no bundles - creates new deepCodeBundle and sets hash", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockSnykCodeClient := deepcodeMocks.NewMockSnykCodeClient(ctrl)
		mockSnykCodeClient.EXPECT().ExtendBundle(gomock.Any(), "testBundleHash", map[string]deepcode.BundleFile{
			"file": {},
		}, []string{}).Return("testBundleHash", []string{}, nil)

		mockSpan := mocks.NewMockSpan(ctrl)
		mockSpan.EXPECT().Context().AnyTimes()
		mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
		mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).AnyTimes()
		mockInstrumentor.EXPECT().Finish(gomock.Any()).AnyTimes()
		mockErrorReporter := mocks.NewMockErrorReporter(ctrl)
		b := bundle.NewBundle(mockSnykCodeClient, mockInstrumentor, mockErrorReporter, &testLogger, "testBundleHash", map[string]deepcode.BundleFile{}, []string{}, []string{})

		err := b.UploadBatch(context.Background(), "testRequestId", bundleWithFiles)
		assert.NoError(t, err)
	})

	t.Run("when existing bundles - extends deepCodeBundle and updates hash", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockSnykCodeClient := deepcodeMocks.NewMockSnykCodeClient(ctrl)
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
		b := bundle.NewBundle(mockSnykCodeClient, mockInstrumentor, mockErrorReporter, &testLogger, "testBundleHash", map[string]deepcode.BundleFile{}, []string{}, []string{})

		err := b.UploadBatch(context.Background(), "testRequestId", bundleWithFiles)
		require.NoError(t, err)
		oldHash := b.GetBundleHash()
		err = b.UploadBatch(context.Background(), "testRequestId", bundleWithMultipleFiles)
		require.NoError(t, err)
		newHash := b.GetBundleHash()
		assert.NotEqual(t, oldHash, newHash)
	})
}
