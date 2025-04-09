package purl

import (
	"fmt"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/package-url/packageurl-go"
	"github.com/safedep/vet/pkg/common"
	"github.com/safedep/vet/pkg/models"
)

// Wraps a PURL parsed response for extensibility. This is internal and will
// be exposed through APIs only
type purlResponseWrapper struct {
	pd       lockfile.PackageDetails
	instance packageurl.PackageURL
}

func (p *purlResponseWrapper) GetPackageDetails() lockfile.PackageDetails {
	return p.pd
}

// ParsePackageUrl parses a PURL string and returns a lockfile.PackageDetails
// While this may seem like a parser concern, we are keeping it separate to avoid
// cyclical dependency problems since we are dividing the parser package into sub-packages
func ParsePackageUrl(purl string) (*purlResponseWrapper, error) {
	instance, err := packageurl.FromString(purl)
	if err != nil {
		return nil, err
	}

	if instance.Version == "" || instance.Version == "latest" {
		ecosystem, err := PurlTypeToPackageV1Ecosystem(instance.Type)
		if err != nil {
			return nil, err
		}

		version, err := common.ResolvePackageLatestVersion(instance.Name, ecosystem)
		if err != nil {
			return nil, err
		}

		instance.Version = version
	}

	ecosystem, err := PurlTypeToEcosystem(instance.Type)
	if err != nil {
		return nil, err
	}

	pd := lockfile.PackageDetails{
		Ecosystem: ecosystem,
		Name:      purlBuildLockfilePackageName(ecosystem, instance.Namespace, instance.Name),
		Version:   instance.Version,
	}

	return &purlResponseWrapper{
		pd:       pd,
		instance: instance,
	}, nil
}

func purlBuildLockfilePackageName(ecosystem lockfile.Ecosystem, group, name string) string {
	if group == "" {
		return name
	}

	switch ecosystem {
	case lockfile.GoEcosystem, lockfile.NpmEcosystem:
		return fmt.Sprintf("%s/%s", group, name)
	case lockfile.MavenEcosystem:
		return fmt.Sprintf("%s:%s", group, name)
	case models.EcosystemGitHubActions:
		return fmt.Sprintf("%s/%s", group, name)
	default:
		return name
	}
}

func PurlTypeToEcosystem(purlType string) (lockfile.Ecosystem, error) {
	knownTypes := map[string]lockfile.Ecosystem{
		packageurl.TypeCargo:    lockfile.CargoEcosystem,
		packageurl.TypeComposer: lockfile.ComposerEcosystem,
		packageurl.TypeGolang:   lockfile.GoEcosystem,
		packageurl.TypeMaven:    lockfile.MavenEcosystem,
		packageurl.TypeNPM:      lockfile.NpmEcosystem,
		packageurl.TypeNuget:    lockfile.NuGetEcosystem,
		packageurl.TypeGem:      lockfile.BundlerEcosystem,
		packageurl.TypePyPi:     lockfile.PipEcosystem,
		"pip":                   lockfile.PipEcosystem,
		"go":                    lockfile.GoEcosystem,
		"rubygems":              lockfile.BundlerEcosystem,
		packageurl.TypeGithub:   models.EcosystemGitHubActions,
		"actions":               models.EcosystemGitHubActions,
	}

	ecosystem, ok := knownTypes[purlType]
	if !ok {
		return lockfile.Ecosystem(""),
			fmt.Errorf("failed to map PURL type:%s to known ecosystem", purlType)
	}

	return ecosystem, nil
}

func PurlTypeToPackageV1Ecosystem(purlType string) (packagev1.Ecosystem, error) {
	knownTypes := map[string]packagev1.Ecosystem{
		packageurl.TypeCargo:    packagev1.Ecosystem_ECOSYSTEM_CARGO,
		packageurl.TypeComposer: packagev1.Ecosystem_ECOSYSTEM_PACKAGIST,
		packageurl.TypeGolang:   packagev1.Ecosystem_ECOSYSTEM_GO,
		packageurl.TypeMaven:    packagev1.Ecosystem_ECOSYSTEM_MAVEN,
		packageurl.TypeNPM:      packagev1.Ecosystem_ECOSYSTEM_NPM,
		packageurl.TypeNuget:    packagev1.Ecosystem_ECOSYSTEM_NUGET,
		packageurl.TypeGem:      packagev1.Ecosystem_ECOSYSTEM_RUBYGEMS,
		packageurl.TypePyPi:     packagev1.Ecosystem_ECOSYSTEM_PYPI,
		"pip":                   packagev1.Ecosystem_ECOSYSTEM_PYPI,
		"go":                    packagev1.Ecosystem_ECOSYSTEM_GO,
		"rubygems":              packagev1.Ecosystem_ECOSYSTEM_RUBYGEMS,
		packageurl.TypeGithub:   packagev1.Ecosystem_ECOSYSTEM_GITHUB_ACTIONS,
		"actions":               packagev1.Ecosystem_ECOSYSTEM_GITHUB_ACTIONS,
	}

	ecosystem, ok := knownTypes[purlType]
	if !ok {
		return packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED,
			fmt.Errorf("failed to map PURL type:%s to known ecosystem", purlType)
	}

	return ecosystem, nil
}
