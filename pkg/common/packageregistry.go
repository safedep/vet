package common

import (
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/packageregistry"
)

// GetPackageRegistryClient returns a package registry client for the given ecosystem
func GetPackageRegistryClient(ecosystem packagev1.Ecosystem) (packageregistry.Client, error) {
	switch ecosystem {
	case packagev1.Ecosystem_ECOSYSTEM_NPM:
		return packageregistry.NewNpmAdapter()
	case packagev1.Ecosystem_ECOSYSTEM_PYPI:
		return packageregistry.NewPypiAdapter()
	case packagev1.Ecosystem_ECOSYSTEM_RUBYGEMS:
		return packageregistry.NewRubyAdapter()
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %s", ecosystem)
	}
}

// ResolvePackageLatestVersion resolves the latest version of a package
// from the package registry
func ResolvePackageLatestVersion(pkgName string, pkgEcosystem packagev1.Ecosystem) (string, error) {
	pkg, err := GetPackageRegistryClient(pkgEcosystem)
	if err != nil {
		return "", err
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
