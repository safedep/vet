package sbom_utils

import (
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/package-url/packageurl-go"
)

// ParsePurlType parses a package URL (purl) type and returns the corresponding lockfile.Ecosystem.
// It also returns a boolean indicating whether the provided purl type is recognized.
// The recognized purl types are mapped to their corresponding lockfile ecosystems.
func ParsePurlType(purl_type string) (lockfile.Ecosystem, bool) {
	// KnownTypes maps recognized package URL types to their corresponding lockfile ecosystems.
	KnownTypes := map[string]lockfile.Ecosystem{
		packageurl.TypeCargo:    lockfile.CargoEcosystem,
		packageurl.TypeComposer: lockfile.ComposerEcosystem,
		packageurl.TypeGolang:   lockfile.GoEcosystem,
		packageurl.TypeMaven:    lockfile.MavenEcosystem,
		packageurl.TypeNPM:      lockfile.NpmEcosystem,
		packageurl.TypeNuget:    lockfile.NuGetEcosystem,
		packageurl.TypePyPi:     lockfile.PipEcosystem,
		"pip":                   lockfile.PipEcosystem,
		"go":                    lockfile.GoEcosystem,
	}

	// Look up the provided purl_type in the KnownTypes map.
	// eco holds the corresponding lockfile ecosystem, and ok indicates if the purl type is recognized.
	eco, ok := KnownTypes[purl_type]
	return eco, ok
}
