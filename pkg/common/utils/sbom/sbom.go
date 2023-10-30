package sbom

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/pkg/common/purl"
)

// DEPRECATED: Use purl.PurlTypeToEcosystem directly
func PurlTypeToLockfileEcosystem(purl_type string) (lockfile.Ecosystem, error) {
	return purl.PurlTypeToEcosystem(purl_type)
}
