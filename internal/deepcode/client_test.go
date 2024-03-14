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
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/google/uuid"
	"github.com/snyk/code-client-go/internal/deepcode"
	mocks2 "github.com/snyk/code-client-go/internal/http/mocks"
	"github.com/snyk/code-client-go/observability/mocks"
	"github.com/snyk/go-application-framework/pkg/configuration"
	"github.com/snyk/go-application-framework/pkg/workflow"
	"github.com/stretchr/testify/assert"

	"github.com/snyk/code-client-go/internal/util"
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
	mockHTTPClient := mocks2.NewMockHTTPClient(ctrl)
	mockHTTPClient.EXPECT().DoCall(gomock.Any(), gomock.Any(), "http://fake-host", "GET", "/filters", gomock.Any()).Return([]byte(`{"configFiles": ["test"], "extensions": ["test"]}`), nil).Times(1)
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).Times(1)
	mockInstrumentor.EXPECT().Finish(gomock.Any()).Times(1)

	s := deepcode.NewSnykCodeClient(mockHTTPClient, mockInstrumentor, workflow.NewDefaultWorkFlowEngine())
	filters, err := s.GetFilters(context.Background(), "http://fake-host")
	assert.Nil(t, err)
	assert.Equal(t, 1, len(filters.ConfigFiles))
	assert.Equal(t, 1, len(filters.ConfigFiles))
}

func TestSnykCodeBackendService_CreateBundle(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockSpan := mocks.NewMockSpan(ctrl)
	mockSpan.EXPECT().GetTraceId().AnyTimes()
	mockSpan.EXPECT().Context().AnyTimes()
	mockHTTPClient := mocks2.NewMockHTTPClient(ctrl)
	mockHTTPClient.EXPECT().DoCall(gomock.Any(), gomock.Any(), "http://fake-host", "POST", "/bundle", gomock.Any()).Return([]byte(`{"bundleHash":   "bundleHash", "missingFiles": ["test"]}`), nil).Times(1)
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).Times(1)
	mockInstrumentor.EXPECT().Finish(gomock.Any()).Times(1)

	s := deepcode.NewSnykCodeClient(mockHTTPClient, mockInstrumentor, workflow.NewDefaultWorkFlowEngine())
	files := map[string]string{}
	randomAddition := fmt.Sprintf("\n public void random() { System.out.println(\"%d\") }", time.Now().UnixMicro())
	files[path1] = util.Hash([]byte(content + randomAddition))
	bundleHash, missingFiles, err := s.CreateBundle(context.Background(), "http://fake-host", files)
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
	mockHTTPClient := mocks2.NewMockHTTPClient(ctrl)
	mockHTTPClient.EXPECT().DoCall(gomock.Any(), gomock.Any(), "http://fake-host", "POST", "/bundle", gomock.Any()).Return([]byte(`{"bundleHash":   "bundleHash", "missingFiles": []}`), nil).Times(1)
	mockHTTPClient.EXPECT().DoCall(gomock.Any(), gomock.Any(), "http://fake-host", "PUT", "/bundle/bundleHash", gomock.Any()).Return([]byte(`{"bundleHash":   "bundleHash", "missingFiles": []}`), nil).Times(1)
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)
	mockInstrumentor.EXPECT().StartSpan(gomock.Any(), gomock.Any()).Return(mockSpan).Times(2)
	mockInstrumentor.EXPECT().Finish(gomock.Any()).Times(2)

	s := deepcode.NewSnykCodeClient(mockHTTPClient, mockInstrumentor, workflow.NewDefaultWorkFlowEngine())
	var removedFiles []string
	files := map[string]string{}
	files[path1] = util.Hash([]byte(content))
	bundleHash, _, _ := s.CreateBundle(context.Background(), "http://fake-host", files)
	filesExtend := createTestExtendMap()

	bundleHash, missingFiles, err := s.ExtendBundle(context.Background(), "http://fake-host", bundleHash, filesExtend, removedFiles)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(missingFiles))
	assert.NotEmpty(t, bundleHash)
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

func Test_getCodeApiUrl(t *testing.T) {
	ctrl := gomock.NewController(t)
	mockHTTPClient := mocks2.NewMockHTTPClient(ctrl)
	mockInstrumentor := mocks.NewMockInstrumentor(ctrl)

	t.Run("Changes the URL if FedRAMP", func(t *testing.T) {
		engine := workflow.NewDefaultWorkFlowEngine()
		config := engine.GetConfiguration()
		config.Set(configuration.IS_FEDRAMP, true)
		random, _ := uuid.NewRandom()
		orgUUID := random.String()
		config.Set(configuration.ORGANIZATION, orgUUID)
		engine.SetConfiguration(config)
		s := deepcode.NewSnykCodeClient(mockHTTPClient, mockInstrumentor, engine)

		input := "https://snyk.io/api/v1"
		expected := "https://api.snyk.io/hidden/orgs/" + orgUUID + "/code"

		actual, err := s.FormatCodeApiURL(input)
		assert.Nil(t, err)
		assert.Contains(t, actual, expected)
	})

	t.Run("Does not change the URL if it's not FedRAMP", func(t *testing.T) {
		engine := workflow.NewDefaultWorkFlowEngine()
		config := engine.GetConfiguration()
		config.Set(configuration.IS_FEDRAMP, false)
		engine.SetConfiguration(config)
		s := deepcode.NewSnykCodeClient(mockHTTPClient, mockInstrumentor, engine)

		input := "https://snyk.io/api/v1"
		expected := "https://snyk.io/api/v1"

		actual, err := s.FormatCodeApiURL(input)
		t.Log(input, actual)
		assert.Nil(t, err)
		assert.Contains(t, actual, expected)
	})
}
