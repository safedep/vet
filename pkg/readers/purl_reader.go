package readers

import (
	"fmt"

	"github.com/google/osv-scanner/pkg/lockfile"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/common/purl"
	"github.com/safedep/vet/pkg/common/registry"
	"github.com/safedep/vet/pkg/models"
)

type purlReader struct {
	purlString      string
	packageDetails  lockfile.PackageDetails
	config          PurlReaderConfig
	versionResolver registry.PackageVersionResolver
}

type PurlReaderConfig struct {
	AutoResolveMissingVersions bool
}

func NewPurlReader(purlString string, config PurlReaderConfig,
	versionResolver registry.PackageVersionResolver,
) (PackageManifestReader, error) {
	parsedPurl, err := purl.ParsePackageUrl(purlString)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PURL: %v", err)
	}

	return &purlReader{
		purlString:      purlString,
		packageDetails:  parsedPurl.GetPackageDetails(),
		config:          config,
		versionResolver: versionResolver,
	}, nil
}

func (p *purlReader) Name() string {
	return "PURL Reader"
}

func (p *purlReader) ApplicationName() (string, error) {
	return p.packageDetails.Name, nil
}

func (p *purlReader) EnumManifests(handler func(*models.PackageManifest,
	PackageReader) error,
) error {
	pd := p.packageDetails
	pm := models.NewPackageManifestFromPurl(p.purlString, string(pd.Ecosystem))

	// Create the package so that we can use the package model's mapper functions
	pkg := &models.Package{
		PackageDetails: pd,
		Manifest:       pm,
	}

	version := pkg.GetVersion()
	if (version == "" || version == "latest") && p.config.AutoResolveMissingVersions {
		logger.Infof("PURL Reader: Auto-resolving missing version for %s/%s",
			pkg.GetControlTowerSpecEcosystem(),
			pkg.GetName(),
		)

		version, err := p.versionResolver.ResolvePackageLatestVersion(
			pkg.GetControlTowerSpecEcosystem(),
			pkg.GetName(),
		)
		if err != nil {
			return err
		}

		// Patch the version if we are auto-resolving missing versions
		pkg.Version = version
	}

	pm.AddPackage(pkg)
	return handler(pm, NewManifestModelReader(pm))
}
