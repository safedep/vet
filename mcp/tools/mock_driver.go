package tools

import (
	"context"

	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	"github.com/stretchr/testify/mock"
)

// MockDriver is a reusable mock implementation of mcp.Driver that can be used across all tool tests
type MockDriver struct {
	mock.Mock
}

func (m *MockDriver) GetPackageAvailableVersions(ctx context.Context, p *packagev1.Package) ([]*packagev1.PackageVersion, error) {
	args := m.Called(ctx, p)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*packagev1.PackageVersion), args.Error(1)
}

func (m *MockDriver) GetPackageLatestVersion(ctx context.Context, p *packagev1.Package) (*packagev1.PackageVersion, error) {
	args := m.Called(ctx, p)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*packagev1.PackageVersion), args.Error(1)
}

func (m *MockDriver) GetPackageVersionMalwareReport(ctx context.Context, pv *packagev1.PackageVersion) (*malysisv1pb.Report, error) {
	args := m.Called(ctx, pv)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*malysisv1pb.Report), args.Error(1)
}

func (m *MockDriver) GetPackageVersionVulnerabilities(ctx context.Context, pv *packagev1.PackageVersion) ([]*vulnerabilityv1.Vulnerability, error) {
	args := m.Called(ctx, pv)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*vulnerabilityv1.Vulnerability), args.Error(1)
}


func (m *MockDriver) GetPackageVersionPopularity(ctx context.Context, pv *packagev1.PackageVersion) ([]*packagev1.ProjectInsight, error) {
	args := m.Called(ctx, pv)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*packagev1.ProjectInsight), args.Error(1)
}

func (m *MockDriver) GetPackageVersionLicenseInfo(ctx context.Context, pv *packagev1.PackageVersion) (*packagev1.LicenseMetaList, error) {
	args := m.Called(ctx, pv)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*packagev1.LicenseMetaList), args.Error(1)
}

// NewMockDriver creates a new MockDriver instance
func NewMockDriver() *MockDriver {
	return &MockDriver{}
}