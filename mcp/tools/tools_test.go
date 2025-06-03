package tools

import (
	"errors"
	"testing"

	"github.com/safedep/vet/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockMcpServer is a mock implementation of server.McpServer
type MockMcpServer struct {
	mock.Mock
}

func (m *MockMcpServer) RegisterTool(tool mcp.McpTool) error {
	args := m.Called(tool)
	return args.Error(0)
}

func (m *MockMcpServer) Start() error {
	args := m.Called()
	return args.Error(0)
}

func (m *MockMcpServer) Stop() error {
	args := m.Called()
	return args.Error(0)
}

func TestRegisterAll_Success(t *testing.T) {
	// Create mocks
	mockServer := &MockMcpServer{}
	mockDriver := NewMockDriver()

	// Setup expectations - all tool registrations should succeed
	mockServer.On("RegisterTool", mock.AnythingOfType("*tools.packageMalwareTool")).Return(nil)
	mockServer.On("RegisterTool", mock.AnythingOfType("*tools.packageInsightsTool")).Return(nil)
	mockServer.On("RegisterTool", mock.AnythingOfType("*tools.packageRegistryTool")).Return(nil)

	// Execute the function
	err := RegisterAll(mockServer, mockDriver)

	// Verify results
	assert.NoError(t, err)

	// Verify all expectations were met
	mockServer.AssertExpectations(t)
}

func TestRegisterAll_MalwareToolRegistrationFails(t *testing.T) {
	// Create mocks
	mockServer := &MockMcpServer{}
	mockDriver := NewMockDriver()

	// Setup expectations - malware tool registration fails
	mockServer.On("RegisterTool", mock.AnythingOfType("*tools.packageMalwareTool")).Return(errors.New("malware tool registration failed"))

	// Execute the function
	err := RegisterAll(mockServer, mockDriver)

	// Verify results
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malware tool registration failed")

	// Verify expectations were met
	mockServer.AssertExpectations(t)
}

func TestRegisterAll_InsightsToolRegistrationFails(t *testing.T) {
	// Create mocks
	mockServer := &MockMcpServer{}
	mockDriver := NewMockDriver()

	// Setup expectations - malware tool succeeds, insights tool fails
	mockServer.On("RegisterTool", mock.AnythingOfType("*tools.packageMalwareTool")).Return(nil)
	mockServer.On("RegisterTool", mock.AnythingOfType("*tools.packageInsightsTool")).Return(errors.New("insights tool registration failed"))

	// Execute the function
	err := RegisterAll(mockServer, mockDriver)

	// Verify results
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "insights tool registration failed")

	// Verify expectations were met
	mockServer.AssertExpectations(t)
}

func TestRegisterAll_RegistryToolRegistrationFails(t *testing.T) {
	// Create mocks
	mockServer := &MockMcpServer{}
	mockDriver := NewMockDriver()

	// Setup expectations - first two tools succeed, registry tool fails
	mockServer.On("RegisterTool", mock.AnythingOfType("*tools.packageMalwareTool")).Return(nil)
	mockServer.On("RegisterTool", mock.AnythingOfType("*tools.packageInsightsTool")).Return(nil)
	mockServer.On("RegisterTool", mock.AnythingOfType("*tools.packageRegistryTool")).Return(errors.New("registry tool registration failed"))

	// Execute the function
	err := RegisterAll(mockServer, mockDriver)

	// Verify results
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "registry tool registration failed")

	// Verify expectations were met
	mockServer.AssertExpectations(t)
}