// Code generated by MockGen. DO NOT EDIT.
// Source: error_reporter.go

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	observability "github.com/snyk/code-client-go/observability"
)

// MockErrorReporter is a mock of ErrorReporter interface.
type MockErrorReporter struct {
	ctrl     *gomock.Controller
	recorder *MockErrorReporterMockRecorder
}

// MockErrorReporterMockRecorder is the mock recorder for MockErrorReporter.
type MockErrorReporterMockRecorder struct {
	mock *MockErrorReporter
}

// NewMockErrorReporter creates a new mock instance.
func NewMockErrorReporter(ctrl *gomock.Controller) *MockErrorReporter {
	mock := &MockErrorReporter{ctrl: ctrl}
	mock.recorder = &MockErrorReporterMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockErrorReporter) EXPECT() *MockErrorReporterMockRecorder {
	return m.recorder
}

// CaptureError mocks base method.
func (m *MockErrorReporter) CaptureError(err error, options observability.ErrorReporterOptions) bool {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CaptureError", err, options)
	ret0, _ := ret[0].(bool)
	return ret0
}

// CaptureError indicates an expected call of CaptureError.
func (mr *MockErrorReporterMockRecorder) CaptureError(err, options interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CaptureError", reflect.TypeOf((*MockErrorReporter)(nil).CaptureError), err, options)
}

// FlushErrorReporting mocks base method.
func (m *MockErrorReporter) FlushErrorReporting() {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "FlushErrorReporting")
}

// FlushErrorReporting indicates an expected call of FlushErrorReporting.
func (mr *MockErrorReporterMockRecorder) FlushErrorReporting() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "FlushErrorReporting", reflect.TypeOf((*MockErrorReporter)(nil).FlushErrorReporting))
}
