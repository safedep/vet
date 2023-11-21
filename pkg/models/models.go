package models

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"sync"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/gen/insightapi"

	modelspec "github.com/safedep/vet/gen/models"
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
	EcosystemCyDxSBOM  = "CycloneDxSbom"
	EcosystemSpdxSBOM  = "SpdxSbom"
)

// Represents a package manifest that contains a list
// of packages. Example: pom.xml, requirements.txt
type PackageManifest struct {
	// Filesystem path of this manifest
	Path string `json:"path"`

	// When we scan non-path entities like Github org / repo
	// then only path doesn't make sense, which is more local
	// temporary file path
	DisplayPath string `json:"display_path"`

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

func (pm *PackageManifest) GetPath() string {
	return pm.Path
}

func (pm *PackageManifest) SetDisplayPath(path string) {
	pm.DisplayPath = path
}

// GetDisplayPath returns the [DisplayPath] if available or fallsback
// to [Path]
func (pm *PackageManifest) GetDisplayPath() string {
	if len(pm.DisplayPath) > 0 {
		return pm.DisplayPath
	}

	return pm.GetPath()
}

func (pm *PackageManifest) Id() string {
	h := fnv.New64a()
	h.Write([]byte(fmt.Sprintf("%s/%s",
		pm.Ecosystem, pm.Path)))

	return strconv.FormatUint(h.Sum64(), 16)
}

func (pm *PackageManifest) GetPackagesCount() int {
	return len(pm.Packages)
}

func (pm *PackageManifest) GetSpecEcosystem() modelspec.Ecosystem {
	switch pm.Ecosystem {
	case EcosystemCargo:
		return modelspec.Ecosystem_Cargo
	case EcosystemGo:
		return modelspec.Ecosystem_Go
	case EcosystemMaven:
		return modelspec.Ecosystem_Maven
	case EcosystemNpm:
		return modelspec.Ecosystem_Npm
	case EcosystemHex:
		return modelspec.Ecosystem_Hex
	case EcosystemRubyGems:
		return modelspec.Ecosystem_RubyGems
	case EcosystemPyPI:
		return modelspec.Ecosystem_PyPI
	case EcosystemPub:
		return modelspec.Ecosystem_Pub
	case EcosystemCyDxSBOM:
		return modelspec.Ecosystem_CycloneDxSBOM
	case EcosystemSpdxSBOM:
		return modelspec.Ecosystem_SpdxSBOM
	case EcosystemPackagist:
		return modelspec.Ecosystem_Packagist
	case EcosystemNuGet:
		return modelspec.Ecosystem_NuGet
	default:
		return modelspec.Ecosystem_UNKNOWN_ECOSYSTEM
	}
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
		strings.ToLower(string(p.PackageDetails.Ecosystem)),
		strings.ToLower(p.PackageDetails.Name),
		strings.ToLower(p.PackageDetails.Version))))

	return strconv.FormatUint(h.Sum64(), 16)
}

// FIXME: For SPDX/CycloneDX, package ecosystem may be different
// from the manifest ecosystem
func (p *Package) GetSpecEcosystem() modelspec.Ecosystem {
	return p.Manifest.GetSpecEcosystem()
}

func (p *Package) GetName() string {
	return p.Name
}

func (p *Package) GetVersion() string {
	return p.Version
}

func (p *Package) ShortName() string {
	return fmt.Sprintf("pkg:%s/%s@%s",
		strings.ToLower(string(p.Ecosystem)),
		strings.ToLower(p.Name), p.Version)
}

func NewPackageDetail(e, n, v string) lockfile.PackageDetails {
	return lockfile.PackageDetails{
		Ecosystem: lockfile.Ecosystem(e),
		CompareAs: lockfile.Ecosystem(e),
		Name:      n,
		Version:   v,
	}
}
