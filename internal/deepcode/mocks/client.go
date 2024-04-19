// Code generated by MockGen. DO NOT EDIT.
// Source: client.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	deepcode "github.com/snyk/code-client-go/internal/deepcode"
)

// MockDeepcodeClient is a mock of DeepcodeClient interface.
type MockDeepcodeClient struct {
	ctrl     *gomock.Controller
	recorder *MockDeepcodeClientMockRecorder
}

// MockDeepcodeClientMockRecorder is the mock recorder for MockDeepcodeClient.
type MockDeepcodeClientMockRecorder struct {
	mock *MockDeepcodeClient
}

// NewMockDeepcodeClient creates a new mock instance.
func NewMockDeepcodeClient(ctrl *gomock.Controller) *MockDeepcodeClient {
	mock := &MockDeepcodeClient{ctrl: ctrl}
	mock.recorder = &MockDeepcodeClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockDeepcodeClient) EXPECT() *MockDeepcodeClientMockRecorder {
	return m.recorder
}

// CreateBundle mocks base method.
func (m *MockDeepcodeClient) CreateBundle(ctx context.Context, files map[string]string) (string, []string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateBundle", ctx, files)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].([]string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// CreateBundle indicates an expected call of CreateBundle.
func (mr *MockDeepcodeClientMockRecorder) CreateBundle(ctx, files interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateBundle", reflect.TypeOf((*MockDeepcodeClient)(nil).CreateBundle), ctx, files)
}

// ExtendBundle mocks base method.
func (m *MockDeepcodeClient) ExtendBundle(ctx context.Context, bundleHash string, files map[string]deepcode.BundleFile, removedFiles []string) (string, []string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ExtendBundle", ctx, bundleHash, files, removedFiles)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].([]string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ExtendBundle indicates an expected call of ExtendBundle.
func (mr *MockDeepcodeClientMockRecorder) ExtendBundle(ctx, bundleHash, files, removedFiles interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ExtendBundle", reflect.TypeOf((*MockDeepcodeClient)(nil).ExtendBundle), ctx, bundleHash, files, removedFiles)
}

// GetFilters mocks base method.
func (m *MockDeepcodeClient) GetFilters(ctx context.Context) (deepcode.FiltersResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetFilters", ctx)
	ret0, _ := ret[0].(deepcode.FiltersResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetFilters indicates an expected call of GetFilters.
func (mr *MockDeepcodeClientMockRecorder) GetFilters(ctx interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetFilters", reflect.TypeOf((*MockDeepcodeClient)(nil).GetFilters), ctx)
}
