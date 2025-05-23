// Code generated by MockGen. DO NOT EDIT.
// Source: bundle_manager.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	bundle "github.com/snyk/code-client-go/bundle"
	deepcode "github.com/snyk/code-client-go/internal/deepcode"
)

// MockBundleManager is a mock of BundleManager interface.
type MockBundleManager struct {
	ctrl     *gomock.Controller
	recorder *MockBundleManagerMockRecorder
}

// MockBundleManagerMockRecorder is the mock recorder for MockBundleManager.
type MockBundleManagerMockRecorder struct {
	mock *MockBundleManager
}

// NewMockBundleManager creates a new mock instance.
func NewMockBundleManager(ctrl *gomock.Controller) *MockBundleManager {
	mock := &MockBundleManager{ctrl: ctrl}
	mock.recorder = &MockBundleManagerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockBundleManager) EXPECT() *MockBundleManagerMockRecorder {
	return m.recorder
}

// Create mocks base method.
func (m *MockBundleManager) Create(ctx context.Context, requestId, rootPath string, filePaths <-chan string, changedFiles map[string]bool) (bundle.Bundle, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", ctx, requestId, rootPath, filePaths, changedFiles)
	ret0, _ := ret[0].(bundle.Bundle)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Create indicates an expected call of Create.
func (mr *MockBundleManagerMockRecorder) Create(ctx, requestId, rootPath, filePaths, changedFiles interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockBundleManager)(nil).Create), ctx, requestId, rootPath, filePaths, changedFiles)
}

// Upload mocks base method.
func (m *MockBundleManager) Upload(ctx context.Context, requestId string, originalBundle bundle.Bundle, files map[string]deepcode.BundleFile) (bundle.Bundle, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Upload", ctx, requestId, originalBundle, files)
	ret0, _ := ret[0].(bundle.Bundle)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Upload indicates an expected call of Upload.
func (mr *MockBundleManagerMockRecorder) Upload(ctx, requestId, originalBundle, files interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Upload", reflect.TypeOf((*MockBundleManager)(nil).Upload), ctx, requestId, originalBundle, files)
}
