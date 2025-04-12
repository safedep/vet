package registry

import (
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/adapters"
	"github.com/safedep/dry/packageregistry"
)

const pvrErrorScope = "packageVersionResolver"

type PackageVersionResolver interface {
	ResolvePackageLatestVersion(ecosystem packagev1.Ecosystem, pkgName string) (string, error)
}

type packageVersionResolver struct {
	githubClient *adapters.GithubClient
}

func NewPackageVersionResolver(gh *adapters.GithubClient) (PackageVersionResolver, error) {
	if gh == nil {
		return nil, fmt.Errorf("%s: github client is nil", pvrErrorScope)
	}

	return &packageVersionResolver{
		githubClient: gh,
	}, nil
}

// ResolvePackageLatestVersion resolves the latest version of a package
// from the package registry
func (r *packageVersionResolver) ResolvePackageLatestVersion(ecosystem packagev1.Ecosystem, pkgName string) (string, error) {
	registry, err := packageregistry.NewRegistryAdapter(ecosystem,
		&packageregistry.RegistryAdapterConfig{
			GitHubClient: r.githubClient,
		})
	if err != nil {
		return "", fmt.Errorf("%s: failed to create package registry client: %v", pvrErrorScope, err)
	}

	discoveryClient, err := registry.PackageDiscovery()
	if err != nil {
		return "", fmt.Errorf("%s: failed to discover package: %v", pvrErrorScope, err)
	}

	pkg, err := discoveryClient.GetPackage(pkgName)
	if err != nil {
		return "", fmt.Errorf("%s: failed to get package data: %v", pvrErrorScope, err)
	}

	return pkg.LatestVersion, nil
}
