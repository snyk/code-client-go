// Code generated by MockGen. DO NOT EDIT.
// Source: client.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	deepcode2 "github.com/snyk/code-client-go/internal/deepcode"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
<<<<<<< HEAD
	deepcode "github.com/snyk/code-client-go/internal/deepcode"
=======
>>>>>>> 13ff562 (refactor: move the deepcode package)
)

// MockSnykCodeClient is a mock of SnykCodeClient interface.
type MockSnykCodeClient struct {
	ctrl     *gomock.Controller
	recorder *MockSnykCodeClientMockRecorder
}

// MockSnykCodeClientMockRecorder is the mock recorder for MockSnykCodeClient.
type MockSnykCodeClientMockRecorder struct {
	mock *MockSnykCodeClient
}

// NewMockSnykCodeClient creates a new mock instance.
func NewMockSnykCodeClient(ctrl *gomock.Controller) *MockSnykCodeClient {
	mock := &MockSnykCodeClient{ctrl: ctrl}
	mock.recorder = &MockSnykCodeClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSnykCodeClient) EXPECT() *MockSnykCodeClientMockRecorder {
	return m.recorder
}

// CreateBundle mocks base method.
func (m *MockSnykCodeClient) CreateBundle(ctx context.Context, files map[string]string) (string, []string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateBundle", ctx, files)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].([]string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// CreateBundle indicates an expected call of CreateBundle.
func (mr *MockSnykCodeClientMockRecorder) CreateBundle(ctx, files interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateBundle", reflect.TypeOf((*MockSnykCodeClient)(nil).CreateBundle), ctx, files)
}

// ExtendBundle mocks base method.
func (m *MockSnykCodeClient) ExtendBundle(ctx context.Context, bundleHash string, files map[string]deepcode2.BundleFile, removedFiles []string) (string, []string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExtendBundle", ctx, bundleHash, files, removedFiles)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].([]string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ExtendBundle indicates an expected call of ExtendBundle.
func (mr *MockSnykCodeClientMockRecorder) ExtendBundle(ctx, bundleHash, files, removedFiles interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExtendBundle", reflect.TypeOf((*MockSnykCodeClient)(nil).ExtendBundle), ctx, bundleHash, files, removedFiles)
}

// GetFilters mocks base method.
func (m *MockSnykCodeClient) GetFilters(ctx context.Context) (deepcode2.FiltersResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFilters", ctx)
	ret0, _ := ret[0].(deepcode2.FiltersResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetFilters indicates an expected call of GetFilters.
func (mr *MockSnykCodeClientMockRecorder) GetFilters(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFilters", reflect.TypeOf((*MockSnykCodeClient)(nil).GetFilters), ctx)
}
