package readers

import (
	"github.com/safedep/vet/pkg/exceptions"
	"github.com/safedep/vet/pkg/models"
)

type packageManifestReader struct {
	manifest *models.PackageManifest
}

func NewManifestModelReader(manifest *models.PackageManifest) PackageReader {
	return &packageManifestReader{manifest: manifest}
}

func (r *packageManifestReader) EnumPackages(handler func(pkg *models.Package) error) error {
	return exceptions.AllowedPackages(r.manifest, handler)
}
