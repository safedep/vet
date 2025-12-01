package parser

import (
	"context"
	"fmt"
	"os"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
	"github.com/google/osv-scalibr/fs"

	"github.com/safedep/vet/pkg/models"
)

func parseBunLockFile(lockfilePath string, _ *ParserConfig) (*models.PackageManifest, error) {
	bunExtractor := bunlock.New()

	file, err := os.Open(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open lockfile: %w", err)
	}
	defer func() {
		_ = file.Close()
	}()

	inputConfig := &filesystem.ScanInput{
		FS:     fs.DirFS("."),
		Path:   lockfilePath,
		Reader: file,
	}

	inventory, err := bunExtractor.Extract(context.Background(), inputConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to extract packages: %w", err)
	}

	manifest := models.NewPackageManifestFromLocal(lockfilePath, models.EcosystemNpm)

	for _, pkg := range inventory.Packages {
		pkgDetails := models.NewPackageDetail(models.EcosystemNpm, pkg.Name, pkg.Version)
		modelPackage := &models.Package{
			PackageDetails: pkgDetails,
			Manifest:       manifest,
		}
		manifest.AddPackage(modelPackage)
	}

	return manifest, nil
}
