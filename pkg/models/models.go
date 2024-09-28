package models

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"sync"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
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

	// The package depeneny graph representation
	DependencyGraph *DependencyGraph[*Package] `json:"dependency_graph"`

	// Lock to serialize updating packages
	m sync.Mutex
}

func NewPackageManifest(path, ecosystem string) *PackageManifest {
	return &PackageManifest{
		Path:            path,
		Ecosystem:       ecosystem,
		Packages:        make([]*Package, 0),
		DependencyGraph: NewDependencyGraph[*Package](),
	}
}

func (pm *PackageManifest) AddPackage(pkg *Package) {
	pm.m.Lock()
	defer pm.m.Unlock()

	if pkg.Manifest == nil {
		pkg.Manifest = pm
	}

	pm.Packages = append(pm.Packages, pkg)
	pm.DependencyGraph.AddNode(pkg)
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

// GetPackages returns the list of packages in this manifest
// It uses the DependencyGraph to get the list of packages if available
// else fallsback to the [Packages] field
func (pm *PackageManifest) GetPackages() []*Package {
	if pm.DependencyGraph != nil && pm.DependencyGraph.Present() {
		return pm.DependencyGraph.GetPackages()
	}

	return pm.Packages
}

func (pm *PackageManifest) Id() string {
	return hashedId(fmt.Sprintf("%s/%s",
		pm.Ecosystem, pm.Path))
}

func (pm *PackageManifest) GetPackagesCount() int {
	return len(pm.GetPackages())
}

func (pm *PackageManifest) GetControlTowerSpecEcosystem() packagev1.Ecosystem {
	switch pm.Ecosystem {
	case EcosystemCargo:
		return packagev1.Ecosystem_ECOSYSTEM_CARGO
	case EcosystemGo:
		return packagev1.Ecosystem_ECOSYSTEM_GO
	case EcosystemMaven:
		return packagev1.Ecosystem_ECOSYSTEM_MAVEN
	case EcosystemNpm:
		return packagev1.Ecosystem_ECOSYSTEM_NPM
	default:
		return packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED
	}
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
	Insights *insightapi.PackageVersionInsight `json:"insights,omitempty"`

	// This package is a transitive dependency of parent package
	Parent *Package `json:"-"`

	// Depth of this package in dependency tree
	Depth int `json:"depth"`

	// Manifest from where this package was found directly or indirectly
	Manifest *PackageManifest `json:"-"`
}

// Id returns a unique identifier for this package within a manifest
// It is used to identify a package in the dependency graph
// It should be reproducible across multiple runs
func (p *Package) Id() string {
	return hashedId(fmt.Sprintf("%s/%s/%s",
		strings.ToLower(string(p.PackageDetails.Ecosystem)),
		strings.ToLower(p.PackageDetails.Name),
		strings.ToLower(p.PackageDetails.Version)))
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

func (p *Package) GetDependencyGraph() *DependencyGraph[*Package] {
	if p.Manifest == nil {
		return nil
	}

	if p.Manifest.DependencyGraph == nil {
		return nil
	}

	if !p.Manifest.DependencyGraph.Present() {
		return nil
	}

	return p.Manifest.DependencyGraph
}

// DependencyPath returns the path from a root package to this package
func (p *Package) DependencyPath() []*Package {
	dg := p.GetDependencyGraph()
	if dg == nil {
		return []*Package{}
	}

	return dg.PathToRoot(p)
}

func (p *Package) GetDependencies() ([]*Package, error) {
	graph := p.GetDependencyGraph()
	if graph == nil {
		return nil, fmt.Errorf("dependency graph not available")
	}

	dependencies := []*Package{}

	nodes := graph.GetNodes()
	for _, node := range nodes {
		if node.Root {
			continue
		}

		if node.Data == nil {
			continue
		}

		if p.GetName() != node.Data.GetName() &&
			p.GetVersion() != node.Data.GetVersion() &&
			p.GetSpecEcosystem() != node.Data.GetSpecEcosystem() {
			continue
		}

		dependencies = append(dependencies, node.Children...)
		break
	}

	return dependencies, nil
}

func NewPackageDetail(ecosystem, name, version string) lockfile.PackageDetails {
	return lockfile.PackageDetails{
		Ecosystem: lockfile.Ecosystem(ecosystem),
		CompareAs: lockfile.Ecosystem(ecosystem),
		Name:      name,
		Version:   version,
	}
}

// This is probably not the best place for IdGen but keeping it here
// since this package is the most stable (SDP)
func IdGen(data string) string {
	return hashedId(data)
}

func hashedId(str string) string {
	h := fnv.New64a()
	h.Write([]byte(str))

	return strconv.FormatUint(h.Sum64(), 16)
}
