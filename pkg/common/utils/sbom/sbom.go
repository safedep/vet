package sbom

import (
	"strings"

	"github.com/google/osv-scanner/pkg/lockfile"
	gocvss20 "github.com/pandatix/go-cvss/20"
	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
	gocvss40 "github.com/pandatix/go-cvss/40"

	"github.com/safedep/vet/pkg/common/purl"
)

// DEPRECATED: Use purl.PurlTypeToEcosystem directly
func PurlTypeToLockfileEcosystem(purl_type string) (lockfile.Ecosystem, error) {
	return purl.PurlTypeToEcosystem(purl_type)
}

func CalculateCvssScore(vector string) (float64, error) {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.0"):
		cvss, err := gocvss30.ParseVector(vector)
		if err != nil {
			return 0, err
		}
		return cvss.BaseScore(), nil
	case strings.HasPrefix(vector, "CVSS:3.1"):
		cvss, err := gocvss31.ParseVector(vector)
		if err != nil {
			return 0, err
		}
		return cvss.BaseScore(), nil
	case strings.HasPrefix(vector, "CVSS:4.0"):
		cvss, err := gocvss40.ParseVector(vector)
		if err != nil {
			return 0, err
		}
		return cvss.Score(), nil
	default:
		cvss, err := gocvss20.ParseVector(vector)
		if err != nil {
			return 0, err
		}
		return cvss.BaseScore(), nil
	}
}
