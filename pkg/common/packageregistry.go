package common

import (
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/packageregistry"
)

// ResolvePackageLatestVersion resolves the latest version of a package
// from the package registry
func ResolvePackageLatestVersion(pkgName string, pkgEcosystem packagev1.Ecosystem) (string, error) {
	pkg, err := packageregistry.NewRegistryAdapter(pkgEcosystem)
	if err != nil {
		return "", fmt.Errorf("failed to create package registry client: %v", err)
	}

	pkgPacakgeDiscovery, err := pkg.PackageDiscovery()
	if err != nil {
		return "", fmt.Errorf("failed to discover package: %v", err)
	}

	pkgData, err := pkgPacakgeDiscovery.GetPackage(pkgName)
	if err != nil {
		return "", fmt.Errorf("failed to get package data: %v", err)
	}

	return pkgData.LatestVersion, nil
}
