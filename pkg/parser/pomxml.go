package parser

import (
	"context"
	"fmt"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scalibr/fs"
	"github.com/safedep/vet/pkg/models"
	"os"
)

const mavenCentralRegistry = "https://repo.maven.apache.org/maven2/"

// parseMavenPomXmlFile parses the pom.xml file in a maven project.
// Its finds the dependency from Maven Registry, and also from Parent Maven BOM
// We use osc-scalibr's java/pomxmlnet (with Net, or Network) to fetch dependency from registry.
func parseMavenPomXmlFile(lockfilePath string, _ *ParserConfig) (*models.PackageManifest, error) {
	// Java/PomXMLNet extractor
	pomXmlNetExtractor := pomxmlnet.New(pomxmlnet.NewConfig(mavenCentralRegistry))

	file, err := os.Open(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open lockfile: %s", err)
	}
	defer file.Close()

	inputConfig := &filesystem.ScanInput{
		FS:     fs.DirFS("."),
		Path:   lockfilePath,
		Reader: file,
	}

	inventory, err := pomXmlNetExtractor.Extract(context.Background(), inputConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to extract packages: %s", err)
	}

	manifest := models.NewPackageManifestFromLocal(lockfilePath, models.EcosystemMaven)

	for _, pkg := range inventory.Packages {
		pkgDetails := models.NewPackageDetail(models.EcosystemMaven, pkg.Name, pkg.Version)
		modelPackage := &models.Package{
			PackageDetails: pkgDetails,
			Manifest:       manifest,
		}
		manifest.AddPackage(modelPackage)
	}

	return manifest, nil
}
