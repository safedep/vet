package mcp

import (
	"context"
	"errors"
	"fmt"

	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/insights/v2/insightsv2grpc"
	"buf.build/gen/go/safedep/api/grpc/go/safedep/services/malysis/v1/malysisv1grpc"
	malysisv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	vulnerabilityv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/vulnerability/v1"
	insightsv2 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/insights/v2"
	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/malysis/v1"
	"github.com/safedep/dry/adapters"
	"github.com/safedep/dry/packageregistry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	ErrMaliciousPackageScanningPackageNotFound = errors.New("no known malicious package scanning report found")
	ErrPackageVersionInsightNotFound           = errors.New("no known package version insight found")
	ErrInvalidParameters                       = errors.New("invalid parameters")
)

type DriverConfig struct{}

func DefaultDriverConfig() DriverConfig {
	return DriverConfig{}
}

// Driver is the contract for all the services available in this system.
// Tools use driver to actually perform operations. The purpose of using a Driver
// instead of using services directly in tools is to allow for caching and other stateful
// operations while keeping tools stateless
type Driver interface {
	// Return all available versions for a package
	GetPackageAvailableVersions(ctx context.Context, p *packagev1.Package) ([]*packagev1.PackageVersion, error)

	// Return the latest version for a package
	GetPackageLatestVersion(ctx context.Context, p *packagev1.Package) (*packagev1.PackageVersion, error)

	// Return a malware analysis report for a package version
	GetPackageVersionMalwareReport(ctx context.Context, pv *packagev1.PackageVersion) (*malysisv1pb.Report, error)

	// Return vulnerabilities for a package version
	GetPackageVersionVulnerabilities(ctx context.Context, pv *packagev1.PackageVersion) ([]*vulnerabilityv1.Vulnerability, error)

	// Return popularity insights for a package version
	GetPackageVersionPopularity(ctx context.Context, pv *packagev1.PackageVersion) ([]*packagev1.ProjectInsight, error)

	// Return license information for a package version
	GetPackageVersionLicenseInfo(ctx context.Context, pv *packagev1.PackageVersion) (*packagev1.LicenseMetaList, error)
}

type defaultDriver struct {
	insightsClient insightsv2grpc.InsightServiceClient
	malysisClient  malysisv1grpc.MalwareAnalysisServiceClient
	gh             *adapters.GithubClient
}

var _ Driver = &defaultDriver{}

// NewDefaultDriver creates a new default driver with the given clients
// Always follow dependency inversion principle when extending the driver
func NewDefaultDriver(insightsClient insightsv2grpc.InsightServiceClient,
	malysisClient malysisv1grpc.MalwareAnalysisServiceClient,
	gh *adapters.GithubClient,
) (*defaultDriver, error) {
	if insightsClient == nil {
		return nil, ErrInvalidParameters
	}

	if malysisClient == nil {
		return nil, ErrInvalidParameters
	}

	if gh == nil {
		return nil, ErrInvalidParameters
	}

	return &defaultDriver{
		insightsClient: insightsClient,
		malysisClient:  malysisClient,
		gh:             gh,
	}, nil
}

// GetPackageLatestVersion returns the latest version of a package by querying the package registry
func (d *defaultDriver) GetPackageLatestVersion(ctx context.Context, p *packagev1.Package) (*packagev1.PackageVersion, error) {
	registryClient, err := packageregistry.NewRegistryAdapter(p.Ecosystem, &packageregistry.RegistryAdapterConfig{
		GitHubClient: d.gh,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create registry client: %w", err)
	}

	packageDiscovery, err := registryClient.PackageDiscovery()
	if err != nil {
		return nil, fmt.Errorf("failed to create package discovery: %w", err)
	}

	packageInfo, err := packageDiscovery.GetPackage(p.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get package info: %w", err)
	}

	return &packagev1.PackageVersion{
		Package: &packagev1.Package{
			Ecosystem: p.Ecosystem,
			Name:      p.Name,
		},
		Version: packageInfo.LatestVersion,
	}, nil
}

func (d *defaultDriver) GetPackageAvailableVersions(ctx context.Context, p *packagev1.Package) ([]*packagev1.PackageVersion, error) {
	registryClient, err := packageregistry.NewRegistryAdapter(p.Ecosystem, &packageregistry.RegistryAdapterConfig{
		GitHubClient: d.gh,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create registry client: %w", err)
	}

	packageDiscovery, err := registryClient.PackageDiscovery()
	if err != nil {
		return nil, fmt.Errorf("failed to create package discovery: %w", err)
	}

	packageInfo, err := packageDiscovery.GetPackage(p.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get package info: %w", err)
	}

	packageVersions := make([]*packagev1.PackageVersion, len(packageInfo.Versions))
	for i, v := range packageInfo.Versions {
		packageVersions[i] = &packagev1.PackageVersion{
			Package: p,
			Version: v.Version,
		}
	}

	return packageVersions, nil
}

func (d *defaultDriver) GetPackageVersionMalwareReport(ctx context.Context, pv *packagev1.PackageVersion) (*malysisv1pb.Report, error) {
	if pv == nil {
		return nil, ErrInvalidParameters
	}

	// TODO: Based on config, either use query or active analysis
	res, err := d.malysisClient.QueryPackageAnalysis(ctx, &malysisv1.QueryPackageAnalysisRequest{
		Target: &malysisv1pb.PackageAnalysisTarget{
			PackageVersion: pv,
		},
	})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			return nil, ErrMaliciousPackageScanningPackageNotFound
		}

		return nil, fmt.Errorf("failed to query package analysis: %w", err)
	}

	return res.GetReport(), nil
}

func (d *defaultDriver) GetPackageVersionVulnerabilities(ctx context.Context, pv *packagev1.PackageVersion) ([]*vulnerabilityv1.Vulnerability, error) {
	if pv == nil {
		return nil, ErrInvalidParameters
	}

	res, err := d.insightsClient.GetPackageVersionVulnerabilities(ctx, &insightsv2.GetPackageVersionVulnerabilitiesRequest{
		PackageVersion: pv,
	})
	if err != nil {
		// Handle the case where the package version is not found. This is required otherwise
		// LLMs hallucinates
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			return nil, ErrPackageVersionInsightNotFound
		}

		return nil, fmt.Errorf("failed to get package version vulnerabilities: %w", err)
	}

	return res.GetVulnerabilities(), nil
}

func (d *defaultDriver) GetPackageVersionPopularity(ctx context.Context, pv *packagev1.PackageVersion) ([]*packagev1.ProjectInsight, error) {
	insight, err := d.getPackageVersionInsight(ctx, pv)
	if err != nil {
		return nil, fmt.Errorf("failed to get package version insight: %w", err)
	}

	return insight.GetProjectInsights(), nil
}

func (d *defaultDriver) GetPackageVersionLicenseInfo(ctx context.Context, pv *packagev1.PackageVersion) (*packagev1.LicenseMetaList, error) {
	insight, err := d.getPackageVersionInsight(ctx, pv)
	if err != nil {
		return nil, fmt.Errorf("failed to get package version insight: %w", err)
	}

	return insight.GetLicenses(), nil
}

func (d *defaultDriver) getPackageVersionInsight(ctx context.Context, pv *packagev1.PackageVersion) (*packagev1.PackageVersionInsight, error) {
	if pv == nil {
		return nil, ErrInvalidParameters
	}

	res, err := d.insightsClient.GetPackageVersionInsight(ctx, &insightsv2.GetPackageVersionInsightRequest{
		PackageVersion: pv,
	})
	if err != nil {
		// Handle the case where the package version is not found. This is required otherwise
		// LLMs hallucinates
		if s, ok := status.FromError(err); ok && s.Code() == codes.NotFound {
			return nil, ErrPackageVersionInsightNotFound
		}

		return nil, fmt.Errorf("failed to get package version insight: %w", err)
	}

	return res.GetInsight(), nil
}
