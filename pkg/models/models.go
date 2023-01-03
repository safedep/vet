package models

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"sync"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/gen/insightapi"
)

const (
	EcosystemMaven     = "Maven"
	EcosystemRubyGems  = "RubyGems"
	EcosystemGo        = "Go"
	EcosystemNpm       = "npm"
	EcosystemPyPI      = "PyPI"
	EcosystemCargo     = "Cargo"
	EcosystemNuGet     = "NuGet"
	EcosystemPackagist = "Packagist"
	EcosystemHex       = "Hex"
	EcosystemPub       = "Pub"
)

// Represents a package manifest that contains a list
// of packages. Example: pom.xml, requirements.txt
type PackageManifest struct {
	// Filesystem path of this manifest
	Path string `json:"path"`

	// Ecosystem to interpret this manifest
	Ecosystem string `json:"ecosystem"`

	// List of packages obtained by parsing the manifest
	Packages []*Package `json:"packages"`

	// Lock to serialize updating packages
	m sync.Mutex
}

func (pm *PackageManifest) AddPackage(pkg *Package) {
	pm.m.Lock()
	defer pm.m.Unlock()

	pm.Packages = append(pm.Packages, pkg)
}

// Represents a package such as a version of a library defined as a dependency
// in Gemfile.lock, pom.xml etc.
type Package struct {
	lockfile.PackageDetails `json:"package_detail"`

	// Insights obtained for this package
	Insights *insightapi.PackageVersionInsight `json:"insights"`

	// This package is a transitive dependency of parent package
	Parent *Package `json:"-"`

	// Depth of this package in dependency tree
	Depth int `json:"depth"`

	// Manifest from where this package was found directly or indirectly
	Manifest *PackageManifest `json:"-"`
}

func (p *Package) Id() string {
	h := fnv.New64a()
	h.Write([]byte(fmt.Sprintf("%s/%s/%s",
		strings.ToLower(p.Manifest.Ecosystem),
		strings.ToLower(p.PackageDetails.Name),
		strings.ToLower(p.PackageDetails.Version))))

	return strconv.FormatUint(h.Sum64(), 16)
}

func NewPackageDetail(e, n, v string) lockfile.PackageDetails {
	return lockfile.PackageDetails{
		Ecosystem: lockfile.Ecosystem(e),
		CompareAs: lockfile.Ecosystem(e),
		Name:      n,
		Version:   v,
	}
}
