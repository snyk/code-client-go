// Code generated by MockGen. DO NOT EDIT.
// Source: bundle.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	bundle "github.com/snyk/code-client-go/bundle"
	deepcode "github.com/snyk/code-client-go/deepcode"
)

// MockBundle is a mock of Bundle interface.
type MockBundle struct {
	ctrl     *gomock.Controller
	recorder *MockBundleMockRecorder
}

// MockBundleMockRecorder is the mock recorder for MockBundle.
type MockBundleMockRecorder struct {
	mock *MockBundle
}

// NewMockBundle creates a new mock instance.
func NewMockBundle(ctrl *gomock.Controller) *MockBundle {
	mock := &MockBundle{ctrl: ctrl}
	mock.recorder = &MockBundleMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBundle) EXPECT() *MockBundleMockRecorder {
	return m.recorder
}

// GetBundleHash mocks base method.
func (m *MockBundle) GetBundleHash() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetBundleHash")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetBundleHash indicates an expected call of GetBundleHash.
func (mr *MockBundleMockRecorder) GetBundleHash() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetBundleHash", reflect.TypeOf((*MockBundle)(nil).GetBundleHash))
}

// GetFiles mocks base method.
func (m *MockBundle) GetFiles() map[string]deepcode.BundleFile {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFiles")
	ret0, _ := ret[0].(map[string]deepcode.BundleFile)
	return ret0
}

// GetFiles indicates an expected call of GetFiles.
func (mr *MockBundleMockRecorder) GetFiles() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFiles", reflect.TypeOf((*MockBundle)(nil).GetFiles))
}

// GetMissingFiles mocks base method.
func (m *MockBundle) GetMissingFiles() []string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetMissingFiles")
	ret0, _ := ret[0].([]string)
	return ret0
}

// GetMissingFiles indicates an expected call of GetMissingFiles.
func (mr *MockBundleMockRecorder) GetMissingFiles() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetMissingFiles", reflect.TypeOf((*MockBundle)(nil).GetMissingFiles))
}

// GetRequestId mocks base method.
func (m *MockBundle) GetRequestId() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRequestId")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetRequestId indicates an expected call of GetRequestId.
func (mr *MockBundleMockRecorder) GetRequestId() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRequestId", reflect.TypeOf((*MockBundle)(nil).GetRequestId))
}

// GetRootPath mocks base method.
func (m *MockBundle) GetRootPath() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetRootPath")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetRootPath indicates an expected call of GetRootPath.
func (mr *MockBundleMockRecorder) GetRootPath() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetRootPath", reflect.TypeOf((*MockBundle)(nil).GetRootPath))
}

// UploadBatch mocks base method.
func (m *MockBundle) UploadBatch(ctx context.Context, batch *bundle.Batch) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "UploadBatch", ctx, batch)
	ret0, _ := ret[0].(error)
	return ret0
}

// UploadBatch indicates an expected call of UploadBatch.
func (mr *MockBundleMockRecorder) UploadBatch(ctx, batch interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UploadBatch", reflect.TypeOf((*MockBundle)(nil).UploadBatch), ctx, batch)
}
