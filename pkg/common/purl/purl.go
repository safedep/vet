package purl

import (
	"fmt"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/package-url/packageurl-go"
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
