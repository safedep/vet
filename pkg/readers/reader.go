package readers

import "github.com/safedep/vet/pkg/models"

// Contract for implementing package manifest readers such as lockfile parser,
// SBOM parser etc. Reader should stop enumeration and return error if handler
// returns an error
type PackageManifestReader interface {
	EnumManifests(func(*models.PackageManifest) error) error
}

// Contract for implementing a package reader. Enumerator should fail and return
// error if handler fails
type PackageReader interface {
	EnumPackages(func(*models.Package) error) error
}
