package parser

import (
	"context"
	"fmt"
	"os"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/fs"
	"github.com/safedep/vet/pkg/models"
)

// parseGoModFile parses the go.mod file of the  project.
func parseGoModFile(lockfilePath string, config *ParserConfig) (*models.PackageManifest, error) {
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

	cfg := gomod.Config{
		ExcludeIndirect: config.ExcludeTransitiveDependencies,
	}
	goModExtractor := gomod.NewWithConfig(cfg)

	inventory, err := goModExtractor.Extract(context.Background(), inputConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to extract packages: %s", err)
	}

	manifest := models.NewPackageManifestFromLocal(lockfilePath, models.EcosystemGo)

	for _, pkg := range inventory.Packages {
		pkgDetails := models.NewPackageDetail(models.EcosystemGo, pkg.Name, pkg.Version)
		modelPackage := &models.Package{
			PackageDetails: pkgDetails,
			Manifest:       manifest,
		}
		manifest.AddPackage(modelPackage)
	}

	return manifest, nil
}
