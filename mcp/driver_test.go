package mcp

import (
	"context"
	"errors"
	"testing"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/insights/v2/insightsv2grpc"
	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	insightsv2 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/insights/v2"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	"github.com/safedep/dry/adapters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Mock implementations
type mockInsightServiceClient struct {
	mock.Mock
}

func (m *mockInsightServiceClient) GetPackageVersionInsight(ctx context.Context, req *insightsv2.GetPackageVersionInsightRequest, opts ...grpc.CallOption) (*insightsv2.GetPackageVersionInsightResponse, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*insightsv2.GetPackageVersionInsightResponse), args.Error(1)
}

func (m *mockInsightServiceClient) GetPackageVersionVulnerabilities(ctx context.Context, req *insightsv2.GetPackageVersionVulnerabilitiesRequest, opts ...grpc.CallOption) (*insightsv2.GetPackageVersionVulnerabilitiesResponse, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*insightsv2.GetPackageVersionVulnerabilitiesResponse), args.Error(1)
}

type mockMalwareAnalysisServiceClient struct {
	mock.Mock
}

func (m *mockMalwareAnalysisServiceClient) QueryPackageAnalysis(ctx context.Context, req *malysisv1.QueryPackageAnalysisRequest, opts ...grpc.CallOption) (*malysisv1.QueryPackageAnalysisResponse, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*malysisv1.QueryPackageAnalysisResponse), args.Error(1)
}

func (m *mockMalwareAnalysisServiceClient) AnalyzePackage(ctx context.Context, req *malysisv1.AnalyzePackageRequest, opts ...grpc.CallOption) (*malysisv1.AnalyzePackageResponse, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*malysisv1.AnalyzePackageResponse), args.Error(1)
}

func (m *mockMalwareAnalysisServiceClient) GetAnalysisReport(ctx context.Context, req *malysisv1.GetAnalysisReportRequest, opts ...grpc.CallOption) (*malysisv1.GetAnalysisReportResponse, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*malysisv1.GetAnalysisReportResponse), args.Error(1)
}

func (m *mockMalwareAnalysisServiceClient) InternalAnalyzePackage(ctx context.Context, req *malysisv1.InternalAnalyzePackageRequest, opts ...grpc.CallOption) (*malysisv1.InternalAnalyzePackageResponse, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*malysisv1.InternalAnalyzePackageResponse), args.Error(1)
}

func (m *mockMalwareAnalysisServiceClient) ListPackageAnalysisRecords(ctx context.Context, req *malysisv1.ListPackageAnalysisRecordsRequest, opts ...grpc.CallOption) (*malysisv1.ListPackageAnalysisRecordsResponse, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*malysisv1.ListPackageAnalysisRecordsResponse), args.Error(1)
}

func (m *mockMalwareAnalysisServiceClient) InternalAgenticAnalyzePackage(ctx context.Context, req *malysisv1.InternalAgenticAnalyzePackageRequest, opts ...grpc.CallOption) (*malysisv1.InternalAgenticAnalyzePackageResponse, error) {
	args := m.Called(ctx, req, opts)
	return args.Get(0).(*malysisv1.InternalAgenticAnalyzePackageResponse), args.Error(1)
}

// Test helper functions
func createTestPackageVersion() *packagev1.PackageVersion {
	return &packagev1.PackageVersion{
		Package: &packagev1.Package{
			Ecosystem: packagev1.Ecosystem_ECOSYSTEM_NPM,
			Name:      "test-package",
		},
		Version: "1.0.0",
	}
}

func TestNewDefaultDriver(t *testing.T) {
	tests := []struct {
		name           string
		insightsClient insightsv2grpc.InsightServiceClient
		malysisClient  malysisv1grpc.MalwareAnalysisServiceClient
		gh             *adapters.GithubClient
		expectError    bool
	}{
		{
			name:           "successful creation",
			insightsClient: &mockInsightServiceClient{},
			malysisClient:  &mockMalwareAnalysisServiceClient{},
			gh:             &adapters.GithubClient{},
			expectError:    false,
		},
		{
			name:           "creation with nil clients",
			insightsClient: nil,
			malysisClient:  nil,
			gh:             nil,
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			driver, err := NewDefaultDriver(tt.insightsClient, tt.malysisClient, tt.gh)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, driver)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, driver)
				assert.Equal(t, tt.insightsClient, driver.insightsClient)
				assert.Equal(t, tt.malysisClient, driver.malysisClient)
				assert.Equal(t, tt.gh, driver.gh)
			}
		})
	}
}

func TestDefaultDriver_GetPackageVersionMalwareReport(t *testing.T) {
	tests := []struct {
		name           string
		packageVersion *packagev1.PackageVersion
		setupMock      func(*mockMalwareAnalysisServiceClient)
		expectedError  error
		expectReport   bool
	}{
		{
			name:           "successful malware report retrieval",
			packageVersion: createTestPackageVersion(),
			setupMock: func(m *mockMalwareAnalysisServiceClient) {
				response := &malysisv1.QueryPackageAnalysisResponse{
					Report: &malysisv1pb.Report{},
				}
				m.On("QueryPackageAnalysis", mock.Anything, mock.AnythingOfType("*malysisv1.QueryPackageAnalysisRequest"), mock.Anything).Return(response, nil)
			},
			expectedError: nil,
			expectReport:  true,
		},
		{
			name:           "package not found",
			packageVersion: createTestPackageVersion(),
			setupMock: func(m *mockMalwareAnalysisServiceClient) {
				m.On("QueryPackageAnalysis", mock.Anything,
					mock.AnythingOfType("*malysisv1.QueryPackageAnalysisRequest"), mock.Anything).
					Return((*malysisv1.QueryPackageAnalysisResponse)(nil), status.Error(codes.NotFound, "not found"))
			},
			expectedError: ErrMaliciousPackageScanningPackageNotFound,
			expectReport:  false,
		},
		{
			name:           "grpc error",
			packageVersion: createTestPackageVersion(),
			setupMock: func(m *mockMalwareAnalysisServiceClient) {
				m.On("QueryPackageAnalysis", mock.Anything,
					mock.AnythingOfType("*malysisv1.QueryPackageAnalysisRequest"), mock.Anything).
					Return((*malysisv1.QueryPackageAnalysisResponse)(nil), status.Error(codes.Internal, "internal error"))
			},
			expectedError: errors.New("failed to query package analysis"),
			expectReport:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMalysisClient := &mockMalwareAnalysisServiceClient{}
			mockInsightsClient := &mockInsightServiceClient{}
			tt.setupMock(mockMalysisClient)

			driver, err := NewDefaultDriver(mockInsightsClient, mockMalysisClient, &adapters.GithubClient{})
			require.NoError(t, err)

			report, err := driver.GetPackageVersionMalwareReport(context.Background(), tt.packageVersion)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.expectReport {
				assert.NotNil(t, report)
			} else {
				assert.Nil(t, report)
			}

			mockMalysisClient.AssertExpectations(t)
		})
	}
}

func TestDefaultDriver_GetPackageVersionVulnerabilities(t *testing.T) {
	tests := []struct {
		name           string
		packageVersion *packagev1.PackageVersion
		setupMock      func(*mockInsightServiceClient)
		expectedError  error
		expectVulns    bool
	}{
		{
			name:           "successful vulnerabilities retrieval",
			packageVersion: createTestPackageVersion(),
			setupMock: func(m *mockInsightServiceClient) {
				response := &insightsv2.GetPackageVersionVulnerabilitiesResponse{
					Vulnerabilities: []*vulnerabilityv1.Vulnerability{
						{
							Id: &vulnerabilityv1.VulnerabilityIdentifier{
								Value: "CVE-2021-1234",
							},
							Summary: "Test vulnerability",
						},
					},
				}
				m.On("GetPackageVersionVulnerabilities", mock.Anything,
					mock.AnythingOfType("*insightsv2.GetPackageVersionVulnerabilitiesRequest"), mock.Anything).Return(response, nil)
			},
			expectedError: nil,
			expectVulns:   true,
		},
		{
			name:           "package version not found",
			packageVersion: createTestPackageVersion(),
			setupMock: func(m *mockInsightServiceClient) {
				m.On("GetPackageVersionVulnerabilities", mock.Anything,
					mock.AnythingOfType("*insightsv2.GetPackageVersionVulnerabilitiesRequest"), mock.Anything).
					Return((*insightsv2.GetPackageVersionVulnerabilitiesResponse)(nil), status.Error(codes.NotFound, "not found"))
			},
			expectedError: ErrPackageVersionInsightNotFound,
			expectVulns:   false,
		},
		{
			name:           "grpc error",
			packageVersion: createTestPackageVersion(),
			setupMock: func(m *mockInsightServiceClient) {
				m.On("GetPackageVersionVulnerabilities", mock.Anything,
					mock.AnythingOfType("*insightsv2.GetPackageVersionVulnerabilitiesRequest"), mock.Anything).
					Return((*insightsv2.GetPackageVersionVulnerabilitiesResponse)(nil), status.Error(codes.Internal, "internal error"))
			},
			expectedError: errors.New("failed to get package version vulnerabilities"),
			expectVulns:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockInsightsClient := &mockInsightServiceClient{}
			mockMalysisClient := &mockMalwareAnalysisServiceClient{}
			tt.setupMock(mockInsightsClient)

			driver, err := NewDefaultDriver(mockInsightsClient, mockMalysisClient, &adapters.GithubClient{})
			require.NoError(t, err)

			vulns, err := driver.GetPackageVersionVulnerabilities(context.Background(), tt.packageVersion)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.expectVulns {
				assert.NotNil(t, vulns)
				assert.Len(t, vulns, 1)
			} else {
				assert.Nil(t, vulns)
			}

			mockInsightsClient.AssertExpectations(t)
		})
	}
}



func TestDefaultDriver_GetPackageVersionPopularity(t *testing.T) {
	tests := []struct {
		name           string
		packageVersion *packagev1.PackageVersion
		setupMock      func(*mockInsightServiceClient)
		expectedError  error
		expectInsights bool
	}{
		{
			name:           "successful popularity retrieval",
			packageVersion: createTestPackageVersion(),
			setupMock: func(m *mockInsightServiceClient) {
				response := &insightsv2.GetPackageVersionInsightResponse{
					Insight: &packagev1.PackageVersionInsight{
						ProjectInsights: []*packagev1.ProjectInsight{
							{
								Project: &packagev1.Project{
									Name: "test-package",
									Type: packagev1.ProjectSourceType_PROJECT_SOURCE_TYPE_GITHUB,
								},
							},
						},
					},
				}
				m.On("GetPackageVersionInsight", mock.Anything,
					mock.AnythingOfType("*insightsv2.GetPackageVersionInsightRequest"), mock.Anything).Return(response, nil)
			},
			expectedError:  nil,
			expectInsights: true,
		},
		{
			name:           "package version not found",
			packageVersion: createTestPackageVersion(),
			setupMock: func(m *mockInsightServiceClient) {
				m.On("GetPackageVersionInsight", mock.Anything,
					mock.AnythingOfType("*insightsv2.GetPackageVersionInsightRequest"), mock.Anything).
					Return((*insightsv2.GetPackageVersionInsightResponse)(nil), status.Error(codes.NotFound, "not found"))
			},
			expectedError:  ErrPackageVersionInsightNotFound,
			expectInsights: false,
		},
		{
			name:           "grpc error",
			packageVersion: createTestPackageVersion(),
			setupMock: func(m *mockInsightServiceClient) {
				m.On("GetPackageVersionInsight", mock.Anything,
					mock.AnythingOfType("*insightsv2.GetPackageVersionInsightRequest"), mock.Anything).
					Return((*insightsv2.GetPackageVersionInsightResponse)(nil), status.Error(codes.Internal, "internal error"))
			},
			expectedError:  errors.New("failed to get package version insight"),
			expectInsights: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockInsightsClient := &mockInsightServiceClient{}
			mockMalysisClient := &mockMalwareAnalysisServiceClient{}
			tt.setupMock(mockInsightsClient)

			driver, err := NewDefaultDriver(mockInsightsClient, mockMalysisClient, &adapters.GithubClient{})
			require.NoError(t, err)

			insights, err := driver.GetPackageVersionPopularity(context.Background(), tt.packageVersion)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.expectInsights {
				assert.NotNil(t, insights)
				assert.Len(t, insights, 1)
			} else {
				assert.Nil(t, insights)
			}

			mockInsightsClient.AssertExpectations(t)
		})
	}
}

func TestDefaultDriver_GetPackageVersionLicenseInfo(t *testing.T) {
	tests := []struct {
		name           string
		packageVersion *packagev1.PackageVersion
		setupMock      func(*mockInsightServiceClient)
		expectedError  error
		expectLicense  bool
	}{
		{
			name:           "successful license info retrieval",
			packageVersion: createTestPackageVersion(),
			setupMock: func(m *mockInsightServiceClient) {
				response := &insightsv2.GetPackageVersionInsightResponse{
					Insight: &packagev1.PackageVersionInsight{
						Licenses: &packagev1.LicenseMetaList{
							Licenses: []*packagev1.LicenseMeta{
								{
									LicenseId: "MIT",
									Name:      "MIT License",
								},
							},
						},
					},
				}
				m.On("GetPackageVersionInsight", mock.Anything,
					mock.AnythingOfType("*insightsv2.GetPackageVersionInsightRequest"), mock.Anything).Return(response, nil)
			},
			expectedError: nil,
			expectLicense: true,
		},
		{
			name:           "package version not found",
			packageVersion: createTestPackageVersion(),
			setupMock: func(m *mockInsightServiceClient) {
				m.On("GetPackageVersionInsight", mock.Anything,
					mock.AnythingOfType("*insightsv2.GetPackageVersionInsightRequest"), mock.Anything).
					Return((*insightsv2.GetPackageVersionInsightResponse)(nil),
						status.Error(codes.NotFound, "not found"))
			},
			expectedError: ErrPackageVersionInsightNotFound,
			expectLicense: false,
		},
		{
			name:           "grpc error",
			packageVersion: createTestPackageVersion(),
			setupMock: func(m *mockInsightServiceClient) {
				m.On("GetPackageVersionInsight", mock.Anything,
					mock.AnythingOfType("*insightsv2.GetPackageVersionInsightRequest"), mock.Anything).
					Return((*insightsv2.GetPackageVersionInsightResponse)(nil),
						status.Error(codes.Internal, "internal error"))
			},
			expectedError: errors.New("failed to get package version insight"),
			expectLicense: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockInsightsClient := &mockInsightServiceClient{}
			mockMalysisClient := &mockMalwareAnalysisServiceClient{}
			tt.setupMock(mockInsightsClient)

			driver, err := NewDefaultDriver(mockInsightsClient, mockMalysisClient, &adapters.GithubClient{})
			require.NoError(t, err)

			licenseInfo, err := driver.GetPackageVersionLicenseInfo(context.Background(), tt.packageVersion)

			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
			}

			if tt.expectLicense {
				assert.NotNil(t, licenseInfo)
				assert.Len(t, licenseInfo.Licenses, 1)
			} else {
				assert.Nil(t, licenseInfo)
			}

			mockInsightsClient.AssertExpectations(t)
		})
	}
}

func TestDefaultDriver_NilInputHandling(t *testing.T) {
	mockInsightsClient := &mockInsightServiceClient{}
	mockMalysisClient := &mockMalwareAnalysisServiceClient{}

	driver, err := NewDefaultDriver(mockInsightsClient, mockMalysisClient, &adapters.GithubClient{})
	require.NoError(t, err)

	// Test all methods with nil package version
	vulns, err := driver.GetPackageVersionVulnerabilities(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, vulns)

	insights, err := driver.GetPackageVersionPopularity(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, insights)

	licenseInfo, err := driver.GetPackageVersionLicenseInfo(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, licenseInfo)

	report, err := driver.GetPackageVersionMalwareReport(context.Background(), nil)
	assert.Error(t, err)
	assert.Nil(t, report)

	mockInsightsClient.AssertExpectations(t)
	mockMalysisClient.AssertExpectations(t)
}
