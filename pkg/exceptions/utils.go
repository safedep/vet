package exceptions

import (
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

// AllowedPackages iterates over packages in the manifest and call handler
// only for packages not in the exempted by exception rules
func AllowedPackages(manifest *models.PackageManifest,
	handler func(pkg *models.Package) error) error {
	packages := manifest.GetPackages()
	for _, pkg := range packages {
		res, err := Apply(pkg)
		if err != nil {
			logger.Errorf("Failed to evaluate exception for %s: %v",
				pkg.ShortName(), err)
			continue
		}

		if res.Matched() {
			logger.Debugf("Ignoring package:%s due to exception rule",
				pkg.ShortName())
			continue
		}

		err = handler(pkg)
		if err != nil {
			return err
		}
	}

	return nil
}
