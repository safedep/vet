package parser

import (
	"context"
	"fmt"
	"os"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/fs"

	"github.com/safedep/vet/pkg/models"
)

// parserCargoLockFile using osv-scalibr to parse rust projects Cargo.lock file and find dependencies
func parseCargoLockFile(lockfilePath string, _ *ParserConfig) (*models.PackageManifest, error) {
	// rust's cargolock extractor
	cargoLockExtractor := cargolock.New()

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

	inventory, err := cargoLockExtractor.Extract(context.Background(), inputConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to extract packages: %s", err)
	}

	manifest := models.NewPackageManifestFromLocal(lockfilePath, models.EcosystemCargo)

	for _, pkg := range inventory.Packages {
		pkgDetails := models.NewPackageDetail(models.EcosystemCargo, pkg.Name, pkg.Version)
		modelPackage := &models.Package{
			PackageDetails: pkgDetails,
			Manifest:       manifest,
		}
		manifest.AddPackage(modelPackage)
	}

	return manifest, nil
}
