package scanner

import (
	"github.com/safedep/vet/pkg/models"
)

// Callback to receive a discovery package dependency
type PackageDependencyCallbackFn func(pkg *models.Package) error

// Enrich meta information associated with
// the package
type PackageMetaEnricher interface {
	// Name of the enricher
	Name() string

	// Enrich the package with meta information
	Enrich(pkg *models.Package, cb PackageDependencyCallbackFn) error

	// Wait for all the enrichments to complete
	Wait() error
}
