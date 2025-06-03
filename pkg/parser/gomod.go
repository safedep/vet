package parser

import (
	"fmt"
	"os"

	"github.com/safedep/vet/pkg/models"
	"golang.org/x/mod/modfile"
)

// parseGoModFile parses the go.mod file of the  project.
func parseGoModFile(lockfilePath string, _ *ParserConfig) (*models.PackageManifest, error) {
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read the file: %w", err)
	}

	file, err := modfile.ParseLax(lockfilePath, data, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to parse go.mod file: %w", err)
	}
	manifest := models.NewPackageManifestFromLocal(lockfilePath, models.EcosystemGo)

	for _, pkg := range file.Require {
		pkgDetails := models.NewPackageDetail(models.EcosystemGo, pkg.Mod.Path, pkg.Mod.Version)
		modelPackage := &models.Package{
			PackageDetails: pkgDetails,
			Manifest:       manifest,
		}
		manifest.AddPackage(modelPackage)
	}

	return manifest, nil
}
