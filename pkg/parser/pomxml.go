package parser

import (
	"context"
	"fmt"
	"os"

	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/clients/resolution"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scalibr/fs"

	"github.com/safedep/vet/pkg/models"
)

// parseMavenPomXmlFile parses the pom.xml file in a maven project.
// Its finds the dependency from Maven Registry, and also from Parent Maven BOM
// We use osc-scalibr's java/pomxmlnet (with Net, or Network) to fetch dependency from registry.
func parseMavenPomXmlFile(lockfilePath string, config *ParserConfig) (*models.PackageManifest, error) {
	registry := datasource.MavenRegistry{ReleasesEnabled: true}
	if config != nil {
		registry.URL = config.MavenUpstreamRegistry
		registry.ID = config.MavenUpstreamRegistryID
		// Private registries often host -SNAPSHOT versions, and Maven Central does not
		registry.SnapshotsEnabled = registry.URL != ""
	}

	if err := ValidateMavenUpstreamRegistry(registry.URL, registry.ID); err != nil {
		return nil, err
	}

	// We make the Maven client here and not with pomxmlnet.New, because pomxmlnet.New
	// cannot set the registry ID. Maven settings.xml credentials are matched by this ID.
	// An empty URL means Maven Central.
	mavenClient, err := datasource.NewMavenRegistryAPIClient(context.Background(), registry, "", false)
	if err != nil {
		return nil, fmt.Errorf("failed to create Maven registry client: %w", err)
	}

	pomXmlNetExtractor := pomxmlnet.Extractor{
		DepClient:   resolution.NewMavenRegistryClientWithAPI(mavenClient),
		MavenClient: mavenClient,
	}

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
