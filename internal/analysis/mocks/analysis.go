// Code generated by MockGen. DO NOT EDIT.
// Source: analysis.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	analysis "github.com/snyk/code-client-go/internal/analysis"
	sarif "github.com/snyk/code-client-go/sarif"
)

// MockAnalysisOrchestrator is a mock of AnalysisOrchestrator interface.
type MockAnalysisOrchestrator struct {
	ctrl     *gomock.Controller
	recorder *MockAnalysisOrchestratorMockRecorder
}

// MockAnalysisOrchestratorMockRecorder is the mock recorder for MockAnalysisOrchestrator.
type MockAnalysisOrchestratorMockRecorder struct {
	mock *MockAnalysisOrchestrator
}

// NewMockAnalysisOrchestrator creates a new mock instance.
func NewMockAnalysisOrchestrator(ctrl *gomock.Controller) *MockAnalysisOrchestrator {
	mock := &MockAnalysisOrchestrator{ctrl: ctrl}
	mock.recorder = &MockAnalysisOrchestratorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockAnalysisOrchestrator) EXPECT() *MockAnalysisOrchestratorMockRecorder {
	return m.recorder
}

// CreateWorkspace mocks base method.
func (m *MockAnalysisOrchestrator) CreateWorkspace(ctx context.Context, orgId, requestId string, path analysis.ScanTarget, bundleHash string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "CreateWorkspace", ctx, orgId, requestId, path, bundleHash)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// CreateWorkspace indicates an expected call of CreateWorkspace.
func (mr *MockAnalysisOrchestratorMockRecorder) CreateWorkspace(ctx, orgId, requestId, path, bundleHash interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "CreateWorkspace", reflect.TypeOf((*MockAnalysisOrchestrator)(nil).CreateWorkspace), ctx, orgId, requestId, path, bundleHash)
}

// RunAnalysis mocks base method.
func (m *MockAnalysisOrchestrator) RunAnalysis(ctx context.Context, orgId, workspaceId string) (*sarif.SarifResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RunAnalysis", ctx, orgId, workspaceId)
	ret0, _ := ret[0].(*sarif.SarifResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RunAnalysis indicates an expected call of RunAnalysis.
func (mr *MockAnalysisOrchestratorMockRecorder) RunAnalysis(ctx, orgId, workspaceId interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RunAnalysis", reflect.TypeOf((*MockAnalysisOrchestrator)(nil).RunAnalysis), ctx, orgId, workspaceId)
}

// MockScannerTarget is a mock of ScanTarget interface.
type MockScannerTarget struct {
	ctrl     *gomock.Controller
	recorder *MockScannerTargetMockRecorder
}

// MockScannerTargetMockRecorder is the mock recorder for MockScannerTarget.
type MockScannerTargetMockRecorder struct {
	mock *MockScannerTarget
}

// NewMockScannerTarget creates a new mock instance.
func NewMockScannerTarget(ctrl *gomock.Controller) *MockScannerTarget {
	mock := &MockScannerTarget{ctrl: ctrl}
	mock.recorder = &MockScannerTargetMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockScannerTarget) EXPECT() *MockScannerTargetMockRecorder {
	return m.recorder
}

// GetPath mocks base method.
func (m *MockScannerTarget) GetPath() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetPath")
	ret0, _ := ret[0].(string)
	return ret0
}

// GetPath indicates an expected call of GetPath.
func (mr *MockScannerTargetMockRecorder) GetPath() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetPath", reflect.TypeOf((*MockScannerTarget)(nil).GetPath))
}
