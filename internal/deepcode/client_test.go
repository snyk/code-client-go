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
package deepcode_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	confMocks "github.com/snyk/code-client-go/config/mocks"
	httpmocks "github.com/snyk/code-client-go/http/mocks"
	"github.com/snyk/code-client-go/internal/deepcode"
	"github.com/snyk/code-client-go/internal/util"
	"github.com/snyk/code-client-go/observability/mocks"
)

const (
	path1   = "/AnnotatorTest.java"
	path2   = "/AnnotatorTest2.java"
	content = `public class AnnotatorTest {
  public static void delay(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }
}`
	content2 = `public class AnnotatorTest2 {
  public static void delay(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      e.printStackTrace();
    }
  }
}`
)

func TestSnykCodeBackendService_GetFilters(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockSpan.EXPECT().Context().AnyTimes()
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().Organization().AnyTimes().Return("")
	mockConfig.EXPECT().IsFedramp().AnyTimes().Return(false)
	mockConfig.EXPECT().SnykCodeApi().AnyTimes().Return("http://localhost")

	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)
	mockHTTPClient.EXPECT().Do(
		mock.MatchedBy(func(i interface{}) bool {
			req := i.(*http.Request)
			return req.URL.String() == "http://localhost/filters" &&
				req.Method == "GET" &&
				req.Header.Get("Cache-Control") == "private, max-age=0, no-cache" &&
				req.Header.Get("Content-Type") == "application/json"
		}),
	).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"configFiles": ["test"], "extensions": ["test"]}`))),
	}, nil).Times(1)

	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).Times(1)
	mockInstrumentor.EXPECT().Finish(gomock.Any()).Times(1)
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

	s := deepcode.NewSnykCodeClient(newLogger(t), mockHTTPClient, mockInstrumentor, mockErrorReporter, mockConfig)
	filters, err := s.GetFilters(context.Background())
	assert.Nil(t, err)
	assert.Equal(t, 1, len(filters.ConfigFiles))
	assert.Equal(t, 1, len(filters.ConfigFiles))
}

func TestSnykCodeBackendService_CreateBundle(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockSpan.EXPECT().Context().AnyTimes()
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().Organization().AnyTimes().Return("")
	mockConfig.EXPECT().IsFedramp().AnyTimes().Return(false)
	mockConfig.EXPECT().SnykCodeApi().AnyTimes().Return("http://localhost")
	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)
	mockHTTPClient.EXPECT().Do(
		mock.MatchedBy(func(i interface{}) bool {
			req := i.(*http.Request)
			return req.URL.String() == "http://localhost/bundle" &&
				req.Method == "POST" &&
				req.Header.Get("Cache-Control") == "private, max-age=0, no-cache" &&
				req.Header.Get("Content-Encoding") == "gzip" &&
				req.Header.Get("Content-Type") == "application/octet-stream"
		}),
	).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"bundleHash":   "bundleHash", "missingFiles": ["test"]}`))),
	}, nil).Times(1)

	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).Times(1)
	mockInstrumentor.EXPECT().Finish(gomock.Any()).Times(1)
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

	s := deepcode.NewSnykCodeClient(newLogger(t), mockHTTPClient, mockInstrumentor, mockErrorReporter, mockConfig)
	files := map[string]string{}
	randomAddition := fmt.Sprintf("\n public void random() { System.out.println(\"%d\") }", time.Now().UnixMicro())
	files[path1] = util.Hash([]byte(content + randomAddition))
	bundleHash, missingFiles, err := s.CreateBundle(context.Background(), files)
	assert.Nil(t, err)
	assert.NotNil(t, bundleHash)
	assert.Equal(t, "bundleHash", bundleHash)
	assert.Equal(t, 1, len(missingFiles))
}

func TestSnykCodeBackendService_ExtendBundle(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockSpan.EXPECT().Context().AnyTimes()
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().Organization().AnyTimes().Return("")
	mockConfig.EXPECT().IsFedramp().AnyTimes().Return(false)
	mockConfig.EXPECT().SnykCodeApi().AnyTimes().Return("http://localhost")
	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)
	mockHTTPClient.EXPECT().Do(
		mock.MatchedBy(func(i interface{}) bool {
			req := i.(*http.Request)
			return req.URL.String() == "http://localhost/bundle" &&
				req.Method == "POST" &&
				req.Header.Get("Cache-Control") == "private, max-age=0, no-cache" &&
				req.Header.Get("Content-Encoding") == "gzip" &&
				req.Header.Get("Content-Type") == "application/octet-stream"
		}),
	).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"bundleHash":   "bundleHash", "missingFiles": []}`))),
	}, nil).Times(1)
	mockHTTPClient.EXPECT().Do(
		mock.MatchedBy(func(i interface{}) bool {
			req := i.(*http.Request)
			return req.URL.String() == "http://localhost/bundle/bundleHash" &&
				req.Method == "PUT" &&
				req.Header.Get("Cache-Control") == "private, max-age=0, no-cache" &&
				req.Header.Get("Content-Encoding") == "gzip" &&
				req.Header.Get("Content-Type") == "application/octet-stream"
		}),
	).Return(&http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte(`{"bundleHash":   "bundleHash", "missingFiles": []}`))),
	}, nil).Times(1)
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).Times(2)
	mockInstrumentor.EXPECT().Finish(gomock.Any()).Times(2)
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

	s := deepcode.NewSnykCodeClient(newLogger(t), mockHTTPClient, mockInstrumentor, mockErrorReporter, mockConfig)
	var removedFiles []string
	files := map[string]string{}
	files[path1] = util.Hash([]byte(content))
	bundleHash, _, _ := s.CreateBundle(context.Background(), files)
	filesExtend := createTestExtendMap()

	bundleHash, missingFiles, err := s.ExtendBundle(context.Background(), bundleHash, filesExtend, removedFiles)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(missingFiles))
	assert.NotEmpty(t, bundleHash)
}

func Test_Host(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockConfig := confMocks.NewMockConfig(ctrl)
	mockConfig.EXPECT().SnykCodeApi().AnyTimes().Return("https://snyk.io/api/v1")
	mockHTTPClient := httpmocks.NewMockHTTPClient(ctrl)
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockErrorReporter := mocks.NewMockErrorReporter(ctrl)

	t.Run("Changes the URL if FedRAMP", func(t *testing.T) {
		mockConfig.EXPECT().Organization().AnyTimes().Return("00000000-0000-0000-0000-000000000023")
		mockConfig.EXPECT().IsFedramp().Times(1).Return(true)

		s := deepcode.NewSnykCodeClient(newLogger(t), mockHTTPClient, mockInstrumentor, mockErrorReporter, mockConfig)

		actual, err := s.Host()
		assert.Nil(t, err)
		assert.Contains(t, actual, "https://api.snyk.io/hidden/orgs/00000000-0000-0000-0000-000000000023/code")
	})

	t.Run("Does not change the URL if it's not FedRAMP", func(t *testing.T) {
		mockConfig.EXPECT().Organization().AnyTimes().Return("")
		mockConfig.EXPECT().IsFedramp().Times(1).Return(false)
		s := deepcode.NewSnykCodeClient(newLogger(t), mockHTTPClient, mockInstrumentor, mockErrorReporter, mockConfig)

		actual, err := s.Host()
		assert.Nil(t, err)
		assert.Contains(t, actual, "https://snyk.io/api/v1")
	})
}

func createTestExtendMap() map[string]deepcode.BundleFile {
	filesExtend := map[string]deepcode.BundleFile{}

	filesExtend[path1] = deepcode.BundleFile{
		Hash:    util.Hash([]byte(content)),
		Content: content,
	}
	filesExtend[path2] = deepcode.BundleFile{
		Hash:    util.Hash([]byte(content2)),
		Content: content2,
	}
	return filesExtend
}

func newLogger(t *testing.T) *zerolog.Logger {
	t.Helper()
	logger := zerolog.New(zerolog.NewTestWriter(t))
	return &logger
}
