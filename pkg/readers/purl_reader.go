package readers

import (
	"fmt"

	"github.com/google/osv-scanner/pkg/lockfile"
	registry "github.com/safedep/vet/internal/registry"
	"github.com/safedep/vet/pkg/common/purl"
	"github.com/safedep/vet/pkg/models"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
)

type purlReader struct {
	purl string
}

func NewPurlReader(purl string) (PackageManifestReader, error) {
	return &purlReader{purl: purl}, nil
}

func (p *purlReader) Name() string {
	return "PURL Reader"
}

func (p *purlReader) ApplicationName() (string, error) {
	parsedPurl, err := purl.ParsePackageUrl(p.purl)
	if err != nil {
		return "", err
	}

	return parsedPurl.GetPackageDetails().Name, nil
}

func (p *purlReader) EnumManifests(handler func(*models.PackageManifest,
	PackageReader) error,
) error {
	parsedPurl, err := purl.ParsePackageUrl(p.purl)
	if err != nil {
		return err
	}

	pd := parsedPurl.GetPackageDetails()
	pm := models.NewPackageManifestFromPurl(p.purl, string(pd.Ecosystem))

	version := pd.Version

	if version == "" || version == "latest" {
		ecosystem, err := lockfileEcosystemToPackageV1Ecosystem(pd.Ecosystem)
		if err != nil {
			return err
		}

		packageName := pd.Name
		version, err := registry.ResolvePackageLatestVersion(packageName, ecosystem)
		if err != nil {
			return err
		}

		pd.Version = version
	}

	pm.AddPackage(&models.Package{
		PackageDetails: pd,
		Manifest:       pm,
	})

	return handler(pm, NewManifestModelReader(pm))
}

func lockfileEcosystemToPackageV1Ecosystem(lf lockfile.Ecosystem) (packagev1.Ecosystem, error) {
	knownTypes := map[lockfile.Ecosystem]packagev1.Ecosystem{
		lockfile.CargoEcosystem:       packagev1.Ecosystem_ECOSYSTEM_CARGO,
		lockfile.ComposerEcosystem:    packagev1.Ecosystem_ECOSYSTEM_PACKAGIST,
		lockfile.GoEcosystem:          packagev1.Ecosystem_ECOSYSTEM_GO,
		lockfile.MavenEcosystem:       packagev1.Ecosystem_ECOSYSTEM_MAVEN,
		lockfile.NpmEcosystem:         packagev1.Ecosystem_ECOSYSTEM_NPM,
		lockfile.NuGetEcosystem:       packagev1.Ecosystem_ECOSYSTEM_NUGET,
		lockfile.BundlerEcosystem:     packagev1.Ecosystem_ECOSYSTEM_RUBYGEMS,
		lockfile.PipEcosystem:         packagev1.Ecosystem_ECOSYSTEM_PYPI,
		models.EcosystemGitHubActions: packagev1.Ecosystem_ECOSYSTEM_GITHUB_ACTIONS,
	}

	ecosystem, ok := knownTypes[lf]
	if !ok {
		return packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED,
			fmt.Errorf("failed to map lockfile ecosystem %s to package ecosystem", string(lf))
	}

	return ecosystem, nil
}
