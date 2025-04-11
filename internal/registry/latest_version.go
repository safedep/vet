package internal

import (
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/adapters"
	"github.com/safedep/dry/packageregistry"
)

const errorScope = "failed to resolve package latest version"

// ResolvePackageLatestVersion resolves the latest version of a package
// from the package registry
func ResolvePackageLatestVersion(pkgName string, pkgEcosystem packagev1.Ecosystem) (string, error) {
	githubClient, err := adapters.NewGithubClient(adapters.DefaultGitHubClientConfig())
	if err != nil {
		return "", fmt.Errorf("%s: failed to create github client: %v", errorScope, err)
	}

	pkg, err := packageregistry.NewRegistryAdapter(pkgEcosystem, &packageregistry.RegistryAdapterConfig{
		GitHubClient: githubClient,
	})
	if err != nil {
		return "", fmt.Errorf("%s: failed to create package registry client: %v", errorScope, err)
	}

	pkgPacakgeDiscovery, err := pkg.PackageDiscovery()
	if err != nil {
		return "", fmt.Errorf("%s: failed to discover package: %v", errorScope, err)
	}

	pkgData, err := pkgPacakgeDiscovery.GetPackage(pkgName)
	if err != nil {
		return "", fmt.Errorf("%s: failed to get package data: %v", errorScope, err)
	}

	return pkgData.LatestVersion, nil
}
