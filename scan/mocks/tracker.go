// Code generated by MockGen. DO NOT EDIT.
// Source: tracker.go

// Package mocks is a generated GoMock package.
package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	scan "github.com/snyk/code-client-go/v2/scan"
)

// MockTrackerFactory is a mock of TrackerFactory interface.
type MockTrackerFactory struct {
	ctrl     *gomock.Controller
	recorder *MockTrackerFactoryMockRecorder
}

// MockTrackerFactoryMockRecorder is the mock recorder for MockTrackerFactory.
type MockTrackerFactoryMockRecorder struct {
	mock *MockTrackerFactory
}

// NewMockTrackerFactory creates a new mock instance.
func NewMockTrackerFactory(ctrl *gomock.Controller) *MockTrackerFactory {
	mock := &MockTrackerFactory{ctrl: ctrl}
	mock.recorder = &MockTrackerFactoryMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTrackerFactory) EXPECT() *MockTrackerFactoryMockRecorder {
	return m.recorder
}

// GenerateTracker mocks base method.
func (m *MockTrackerFactory) GenerateTracker() scan.Tracker {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GenerateTracker")
	ret0, _ := ret[0].(scan.Tracker)
	return ret0
}

// GenerateTracker indicates an expected call of GenerateTracker.
func (mr *MockTrackerFactoryMockRecorder) GenerateTracker() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GenerateTracker", reflect.TypeOf((*MockTrackerFactory)(nil).GenerateTracker))
}

// MockTracker is a mock of Tracker interface.
type MockTracker struct {
	ctrl     *gomock.Controller
	recorder *MockTrackerMockRecorder
}

// MockTrackerMockRecorder is the mock recorder for MockTracker.
type MockTrackerMockRecorder struct {
	mock *MockTracker
}

// NewMockTracker creates a new mock instance.
func NewMockTracker(ctrl *gomock.Controller) *MockTracker {
	mock := &MockTracker{ctrl: ctrl}
	mock.recorder = &MockTrackerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockTracker) EXPECT() *MockTrackerMockRecorder {
	return m.recorder
}

// Begin mocks base method.
func (m *MockTracker) Begin(title, message string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "Begin", title, message)
}

// Begin indicates an expected call of Begin.
func (mr *MockTrackerMockRecorder) Begin(title, message interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Begin", reflect.TypeOf((*MockTracker)(nil).Begin), title, message)
}

// End mocks base method.
func (m *MockTracker) End(message string) {
	m.ctrl.T.Helper()
	m.ctrl.Call(m, "End", message)
}

// End indicates an expected call of End.
func (mr *MockTrackerMockRecorder) End(message interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "End", reflect.TypeOf((*MockTracker)(nil).End), message)
}
