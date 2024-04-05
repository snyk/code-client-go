// Code generated by MockGen. DO NOT EDIT.
// Source: http.go

// Package mocks is a generated GoMock package.
package mocks

import (
	bytes "bytes"
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
)

// MockHTTPClient is a mock of HTTPClient interface.
type MockHTTPClient struct {
	ctrl     *gomock.Controller
	recorder *MockHTTPClientMockRecorder
}

// MockHTTPClientMockRecorder is the mock recorder for MockHTTPClient.
type MockHTTPClientMockRecorder struct {
	mock *MockHTTPClient
}

// NewMockHTTPClient creates a new mock instance.
func NewMockHTTPClient(ctrl *gomock.Controller) *MockHTTPClient {
	mock := &MockHTTPClient{ctrl: ctrl}
	mock.recorder = &MockHTTPClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockHTTPClient) EXPECT() *MockHTTPClientMockRecorder {
	return m.recorder
}

// DoCall mocks base method.
func (m *MockHTTPClient) DoCall(ctx context.Context, host string, headers map[string]string, method, path string, requestBody *bytes.Buffer) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "DoCall", ctx, host, headers, method, path, requestBody)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// DoCall indicates an expected call of DoCall.
func (mr *MockHTTPClientMockRecorder) DoCall(ctx, host, headers, method, path, requestBody interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "DoCall", reflect.TypeOf((*MockHTTPClient)(nil).DoCall), ctx, host, headers, method, path, requestBody)
}
