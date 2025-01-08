// Code generated by MockGen. DO NOT EDIT.
// Source: analysis.go

// Package mocks is a generated GoMock package.
package mocks

import (
	context "context"
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	bundle "github.com/snyk/code-client-go/internal/bundle"
	sarif "github.com/snyk/code-client-go/sarif"
	scan "github.com/snyk/code-client-go/scan"
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
func (m *MockAnalysisOrchestrator) CreateWorkspace(ctx context.Context, orgId, requestId string, path scan.Target, bundleHash string) (string, error) {
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
func (m *MockAnalysisOrchestrator) RunAnalysis(ctx context.Context, orgId, rootPath, workspaceId string) (*sarif.SarifResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RunAnalysis", ctx, orgId, rootPath, workspaceId)
	ret0, _ := ret[0].(*sarif.SarifResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RunAnalysis indicates an expected call of RunAnalysis.
func (mr *MockAnalysisOrchestratorMockRecorder) RunAnalysis(ctx, orgId, rootPath, workspaceId interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RunAnalysis", reflect.TypeOf((*MockAnalysisOrchestrator)(nil).RunAnalysis), ctx, orgId, rootPath, workspaceId)
}

// RunIncrementalAnalysis mocks base method.
func (m *MockAnalysisOrchestrator) RunIncrementalAnalysis(ctx context.Context, orgId, rootPath, workspaceId string, limitToFiles []string) (*sarif.SarifResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RunIncrementalAnalysis", ctx, orgId, rootPath, workspaceId, limitToFiles)
	ret0, _ := ret[0].(*sarif.SarifResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RunIncrementalAnalysis indicates an expected call of RunIncrementalAnalysis.
func (mr *MockAnalysisOrchestratorMockRecorder) RunIncrementalAnalysis(ctx, orgId, rootPath, workspaceId, limitToFiles interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RunIncrementalAnalysis", reflect.TypeOf((*MockAnalysisOrchestrator)(nil).RunIncrementalAnalysis), ctx, orgId, rootPath, workspaceId, limitToFiles)
}

// RunTest mocks base method.
func (m *MockAnalysisOrchestrator) RunTest(ctx context.Context, orgId string, b bundle.Bundle) (*sarif.SarifResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "RunTest", ctx, orgId, b)
	ret0, _ := ret[0].(*sarif.SarifResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// RunTest indicates an expected call of RunTest.
func (mr *MockAnalysisOrchestratorMockRecorder) RunTest(ctx, orgId, b interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "RunTest", reflect.TypeOf((*MockAnalysisOrchestrator)(nil).RunTest), ctx, orgId, b)
}
