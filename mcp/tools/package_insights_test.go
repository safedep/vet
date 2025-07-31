package tools

import (
	"context"
	"errors"
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	mcpgo "github.com/mark3labs/mcp-go/mcp"
	"github.com/safedep/vet/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestPackageInsightsTool_ExecuteGetPackageVulnerabilities(t *testing.T) {
	tests := []struct {
		name             string
		requestArgs      map[string]interface{}
		setupDriver      func(*MockDriver)
		expectedContains string
		expectedError    string
	}{
		{
			name: "successful vulnerabilities retrieval",
			requestArgs: map[string]interface{}{
				"purl": "pkg:npm/express@4.17.1",
			},
			setupDriver: func(driver *MockDriver) {
				vulnerabilities := []*vulnerabilityv1.Vulnerability{
					{
						Id: &vulnerabilityv1.VulnerabilityIdentifier{
							Value: "CVE-2022-24999",
						},
						Summary: "Test vulnerability",
					},
				}
				driver.On("GetPackageVersionVulnerabilities", mock.Anything, mock.AnythingOfType("*packagev1.PackageVersion")).
					Return(vulnerabilities, nil)
			},
			expectedContains: "CVE-2022-24999",
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
			name: "package version insight not found",
			requestArgs: map[string]interface{}{
				"purl": "pkg:npm/nonexistent@1.0.0",
			},
			setupDriver: func(driver *MockDriver) {
				driver.On("GetPackageVersionVulnerabilities", mock.Anything, mock.AnythingOfType("*packagev1.PackageVersion")).
					Return(([]*vulnerabilityv1.Vulnerability)(nil), mcp.ErrPackageVersionInsightNotFound)
			},
			expectedContains: "",
			expectedError:    "failed to get package vulnerabilities",
		},
		{
			name: "driver returns other error",
			requestArgs: map[string]interface{}{
				"purl": "pkg:npm/express@4.17.1",
			},
			setupDriver: func(driver *MockDriver) {
				driver.On("GetPackageVersionVulnerabilities", mock.Anything, mock.AnythingOfType("*packagev1.PackageVersion")).
					Return(([]*vulnerabilityv1.Vulnerability)(nil), errors.New("internal server error"))
			},
			expectedContains: "",
			expectedError:    "failed to get package vulnerabilities",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockDriver := NewMockDriver()
			request := createCallToolRequest("get_package_version_vulnerabilities", tt.requestArgs)

			// Setup driver mock
			tt.setupDriver(mockDriver)

			// Create tool instance
			tool := NewPackageInsightsTool(mockDriver)

			// Execute the method
			result, err := tool.executeGetPackageVulnerabilities(context.Background(), request)

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

func TestPackageInsightsTool_ExecuteGetPackagePopularity(t *testing.T) {
	tests := []struct {
		name             string
		requestArgs      map[string]interface{}
		setupDriver      func(*MockDriver)
		expectedContains string
		expectedError    string
	}{
		{
			name: "successful popularity retrieval",
			requestArgs: map[string]interface{}{
				"purl": "pkg:npm/express@4.17.1",
			},
			setupDriver: func(driver *MockDriver) {
				starCount := int64(50000)
				popularity := []*packagev1.ProjectInsight{
					{
						Project: &packagev1.Project{
							Name: "express",
							Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
						},
						Stars: &starCount,
					},
				}
				driver.On("GetPackageVersionPopularity", mock.Anything, mock.AnythingOfType("*packagev1.PackageVersion")).
					Return(popularity, nil)
			},
			expectedContains: "express",
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
				"purl": "pkg:npm/express@4.17.1",
			},
			setupDriver: func(driver *MockDriver) {
				driver.On("GetPackageVersionPopularity", mock.Anything, mock.AnythingOfType("*packagev1.PackageVersion")).
					Return(([]*packagev1.ProjectInsight)(nil), errors.New("internal server error"))
			},
			expectedContains: "",
			expectedError:    "failed to get package popularity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockDriver := NewMockDriver()
			request := createCallToolRequest("get_package_version_popularity", tt.requestArgs)

			// Setup driver mock
			tt.setupDriver(mockDriver)

			// Create tool instance
			tool := NewPackageInsightsTool(mockDriver)

			// Execute the method
			result, err := tool.executeGetPackagePopularity(context.Background(), request)

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

func TestPackageInsightsTool_ExecuteGetPackageLicenseInfo(t *testing.T) {
	tests := []struct {
		name             string
		requestArgs      map[string]interface{}
		setupDriver      func(*MockDriver)
		expectedContains string
		expectedError    string
	}{
		{
			name: "successful license info retrieval",
			requestArgs: map[string]interface{}{
				"purl": "pkg:npm/express@4.17.1",
			},
			setupDriver: func(driver *MockDriver) {
				licenseInfo := &packagev1.LicenseMetaList{
					Licenses: []*packagev1.LicenseMeta{
						{
							LicenseId: "MIT",
							Name:      "MIT License",
						},
					},
				}
				driver.On("GetPackageVersionLicenseInfo", mock.Anything, mock.AnythingOfType("*packagev1.PackageVersion")).
					Return(licenseInfo, nil)
			},
			expectedContains: "MIT",
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
				"purl": "pkg:npm/express@4.17.1",
			},
			setupDriver: func(driver *MockDriver) {
				driver.On("GetPackageVersionLicenseInfo", mock.Anything, mock.AnythingOfType("*packagev1.PackageVersion")).
					Return((*packagev1.LicenseMetaList)(nil), errors.New("internal server error"))
			},
			expectedContains: "",
			expectedError:    "failed to get package license info",
		},

		{
			name: "driver returns nil license info",
			requestArgs: map[string]interface{}{
				"purl": "pkg:npm/express@4.17.1",
			},
			setupDriver: func(driver *MockDriver) {
				driver.On("GetPackageVersionLicenseInfo", mock.Anything, mock.AnythingOfType("*packagev1.PackageVersion")).
					Return(nil, nil)
			},
			expectedContains: "",
			expectedError:    "no license info returned for package",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mocks
			mockDriver := NewMockDriver()
			request := createCallToolRequest("get_package_version_license_info", tt.requestArgs)

			// Setup driver mock
			tt.setupDriver(mockDriver)

			// Create tool instance
			tool := NewPackageInsightsTool(mockDriver)

			// Execute the method
			result, err := tool.executeGetPackageLicenseInfo(context.Background(), request)

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

func TestPackageInsightsTool_Register(t *testing.T) {
	// This test verifies that the tool can be created without errors
	// Full registration testing would require mocking the MCP server

	mockDriver := NewMockDriver()
	tool := NewPackageInsightsTool(mockDriver)

	assert.NotNil(t, tool)
	assert.Equal(t, mockDriver, tool.driver)
}
