package readers

import (
	"github.com/safedep/vet/pkg/exceptions"
	"github.com/safedep/vet/pkg/models"
)

type packageManifestModelReader struct {
	manifest *models.PackageManifest
}

// NewManifestModelReader creates a PackageReader for a manifest model
// that enforces global exceptions policy to ignore packages based on policy
// It returns a PackageReader that can be used to enumerate all packages in the
// given manifest.
func NewManifestModelReader(manifest *models.PackageManifest) PackageReader {
	return &packageManifestModelReader{manifest: manifest}
}

// EnumPackages enumerates each Package available in the PackageManifest while
// ignoring packages as per global exception policy
func (r *packageManifestModelReader) EnumPackages(handler func(pkg *models.Package) error) error {
	return exceptions.AllowedPackages(r.manifest, handler)
}
