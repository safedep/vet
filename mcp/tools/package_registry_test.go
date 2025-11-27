package tools

import (
	"context"
	"errors"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestPackageRegistryTool_ExecuteGetPackageLatestVersion(t *testing.T) {
	tests := []struct {
		name             string
		requestArgs      map[string]interface{}
		setupDriver      func(*MockDriver)
		expectedContains string
		expectedError    string
	}{
		{
			name: "successful latest version retrieval",
			requestArgs: map[string]interface{}{
				"purl": "pkg:npm/express",
			},
			setupDriver: func(driver *MockDriver) {
				latestVersion := &packagev1.PackageVersion{
					Package: &packagev1.Package{
						Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
						Name:      "express",
					},
					Version: "4.18.2",
				}
				driver.On("GetPackageLatestVersion", mock.Anything, mock.AnythingOfType("*packagev1.Package")).
					Return(latestVersion, nil)
			},
			expectedContains: "4.18.2",
			expectedError:    "",
		},
		{
			name:        "missing purl parameter",
			requestArgs: map[string]interface{}{},
			setupDriver: func(driver *MockDriver) {
				// No setup needed as this test will fail before calling the driver
			},
			expectedContains: "",
			expectedError:    "purl is required",
		},
		{
			name: "invalid purl format",
			requestArgs: map[string]interface{}{
				"purl": "invalid-purl-format",
			},
			setupDriver: func(driver *MockDriver) {
				// No setup needed as this test will fail during purl parsing
			},
			expectedContains: "",
			expectedError:    "invalid purl",
		},
		{
			name: "driver returns error",
			requestArgs: map[string]interface{}{
				"purl": "pkg:npm/express",
			},
			setupDriver: func(driver *MockDriver) {
				driver.On("GetPackageLatestVersion", mock.Anything, mock.AnythingOfType("*packagev1.Package")).
					Return((*packagev1.PackageVersion)(nil), errors.New("registry unavailable"))
			},
			expectedContains: "",
			expectedError:    "failed to get package latest version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockDriver := NewMockDriver()
			request := createCallToolRequest("get_package_latest_version", tt.requestArgs)

			// Setup driver mock
			tt.setupDriver(mockDriver)

			// Create tool instance
			tool := NewPackageRegistryTool(mockDriver)

			// Execute the method
			result, err := tool.executeGetPackageLatestVersion(context.Background(), request)

			// Verify results
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)

				// Check that the result is valid and contains expected data
				if tt.expectedContains != "" {
					assert.False(t, result.IsError)
					assert.Len(t, result.Content, 1)
					// Basic validation that we got a proper result
					expectedResult := mcpgo.NewToolResultText(tt.expectedContains)
					assert.Equal(t, expectedResult.IsError, result.IsError)
					assert.Len(t, result.Content, len(expectedResult.Content))
				}
			}

			// Verify driver expectations were met
			mockDriver.AssertExpectations(t)
		})
	}
}

func TestPackageRegistryTool_ExecuteGetPackageAvailableVersions(t *testing.T) {
	tests := []struct {
		name             string
		requestArgs      map[string]interface{}
		setupDriver      func(*MockDriver)
		expectedContains string
		expectedError    string
	}{
		{
			name: "successful available versions retrieval",
			requestArgs: map[string]interface{}{
				"purl": "pkg:npm/express",
			},
			setupDriver: func(driver *MockDriver) {
				versions := []*packagev1.PackageVersion{
					{
						Package: &packagev1.Package{
							Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
							Name:      "express",
						},
						Version: "4.18.2",
					},
					{
						Package: &packagev1.Package{
							Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
							Name:      "express",
						},
						Version: "4.18.1",
					},
				}
				driver.On("GetPackageAvailableVersions", mock.Anything, mock.AnythingOfType("*packagev1.Package")).
					Return(versions, nil)
			},
			expectedContains: "4.18.2",
			expectedError:    "",
		},
		{
			name:        "missing purl parameter",
			requestArgs: map[string]interface{}{},
			setupDriver: func(driver *MockDriver) {
				// No setup needed as this test will fail before calling the driver
			},
			expectedContains: "",
			expectedError:    "purl is required",
		},
		{
			name: "invalid purl format",
			requestArgs: map[string]interface{}{
				"purl": "invalid-purl-format",
			},
			setupDriver: func(driver *MockDriver) {
				// No setup needed as this test will fail during purl parsing
			},
			expectedContains: "",
			expectedError:    "invalid purl",
		},
		{
			name: "driver returns error",
			requestArgs: map[string]interface{}{
				"purl": "pkg:npm/express",
			},
			setupDriver: func(driver *MockDriver) {
				driver.On("GetPackageAvailableVersions", mock.Anything, mock.AnythingOfType("*packagev1.Package")).
					Return(([]*packagev1.PackageVersion)(nil), errors.New("registry unavailable"))
			},
			expectedContains: "",
			expectedError:    "failed to get package available versions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockDriver := NewMockDriver()
			request := createCallToolRequest("get_package_available_versions", tt.requestArgs)

			// Setup driver mock
			tt.setupDriver(mockDriver)

			// Create tool instance
			tool := NewPackageRegistryTool(mockDriver)

			// Execute the method
			result, err := tool.executeGetPackageAvailableVersions(context.Background(), request)

			// Verify results
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)

				// Check that the result is valid and contains expected data
				if tt.expectedContains != "" {
					assert.False(t, result.IsError)
					assert.Len(t, result.Content, 1)
					// Basic validation that we got a proper result
					expectedResult := mcpgo.NewToolResultText(tt.expectedContains)
					assert.Equal(t, expectedResult.IsError, result.IsError)
					assert.Len(t, result.Content, len(expectedResult.Content))
				}
			}

			// Verify driver expectations were met
			mockDriver.AssertExpectations(t)
		})
	}
}

func TestPackageRegistryTool_Register(t *testing.T) {
	// This test verifies that the tool can be created without errors
	// Full registration testing would require mocking the MCP server

	mockDriver := NewMockDriver()
	tool := NewPackageRegistryTool(mockDriver)

	assert.NotNil(t, tool)
	assert.Equal(t, mockDriver, tool.driver)
}
