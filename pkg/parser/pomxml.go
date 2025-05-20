package parser

import (
	"context"
	"fmt"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
	"github.com/safedep/vet/pkg/models"
)

const mavenRegistryURL = "https://repo.maven.apache.org/maven2"

func parseMavenPomXMLFile(lockfilePath string, config *ParserConfig) (*models.PackageManifest, error) {
	// pomxmlnet Extractor
	// Reference: https://github.com/google/osv-scalibr/blob/main/extractor/filesystem/language/java/pomxmlnet/pomxmlnet.go
	pomXmlNetEx := pomxmlnet.New(pomxmlnet.NewConfig(mavenRegistryURL))

	extractorCap := &plugin.Capabilities{
		OS:            plugin.OSAny,
		Network:       plugin.NetworkAny,
		DirectFS:      true,
		RunningSystem: true,
	}

	scanConfig := &scalibr.ScanConfig{
		ScanRoots: []*fs.ScanRoot{
			{Path: "/"},
		},
		PathsToExtract:       []string{lockfilePath},
		FilesystemExtractors: list.FilterByCapabilities([]filesystem.Extractor{pomXmlNetEx}, extractorCap),
	}

	results := scalibr.New().Scan(context.Background(), scanConfig)

	if results.Status.Status != plugin.ScanStatusSucceeded {
		return nil, fmt.Errorf("osv-scalibr scan failed")
	}

	manifest := &models.PackageManifest{
		Ecosystem: models.EcosystemMaven,
	}

	for _, pkg := range results.Inventory.Packages {
		pkgDetails := models.NewPackageDetail(models.EcosystemMaven, pkg.Name, pkg.Version)
		modelPackage := models.Package{
			PackageDetails: pkgDetails,
			Manifest:       manifest,
		}
		manifest.Packages = append(manifest.Packages, &modelPackage)
	}

	return manifest, nil
}
