// Package readers implements the various supported package manifest reader.
// It defines an independent contract for implementing and reading packages
// from one or more package manifest files. For more details, refer [TDD]
//
// [TDD]: https://github.com/safedep/vet/issues/21#issuecomment-1499633233
package readers

import "github.com/safedep/vet/pkg/models"

type PackageManifestHandlerFn func(*models.PackageManifest, PackageReader) error

// Contract for implementing package manifest readers such as lockfile parser,
// SBOM parser etc. Reader should stop enumeration and return error if handler
// returns an error
type PackageManifestReader interface {
	Name() string
	EnumManifests(func(*models.PackageManifest, PackageReader) error) error
}

// Contract for implementing a package reader. Enumerator should fail and return
// error if handler fails
type PackageReader interface {
	EnumPackages(func(*models.Package) error) error
}
