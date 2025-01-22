package models

import (
	"fmt"
	"hash/fnv"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/gen/insightapi"

	modelspec "github.com/safedep/vet/gen/models"
)

const (
	EcosystemMaven             = "Maven"
	EcosystemRubyGems          = "RubyGems"
	EcosystemGo                = "Go"
	EcosystemNpm               = "npm"
	EcosystemPyPI              = "PyPI"
	EcosystemCargo             = "Cargo"
	EcosystemNuGet             = "NuGet"
	EcosystemPackagist         = "Packagist"
	EcosystemHex               = "Hex"
	EcosystemPub               = "Pub"
	EcosystemCyDxSBOM          = "CycloneDxSbom" // These are not real ecosystems. They are containers
	EcosystemSpdxSBOM          = "SpdxSbom"      // These are not real ecosystems. They are containers
	EcosystemGitHubActions     = "GitHubActions"
	EcosystemTerraform         = "Terraform"
	EcosystemTerraformModule   = "TerraformModule"
	EcosystemTerraformProvider = "TerraformProvider"
)

type ManifestSourceType string

const (
	ManifestSourceLocal         = ManifestSourceType("local")
	ManifestSourcePurl          = ManifestSourceType("purl")
	ManifestSourceGitRepository = ManifestSourceType("git_repository")
)

// We now have different sources from where a package
// manifest can be identified. For example, local, github,
// and may be in future within containers or archives like
// JAR. So we need to store additional internal metadata
type PackageManifestSource struct {
	// The source type of this package namespace
	Type ManifestSourceType `json:"type"`

	// The namespace of the package manifest. Examples:
	// - Directory when source is local
	// - GitHub repo URL when source is GitHub
	Namespace string `json:"namespace"`

	// The namespace relative path of the package manifest.
	// This is an actually referenceable identifier to the data
	Path string `json:"path"`

	// Explicit override the display path
	DisplayPath string `json:"display_path"`
}

func (ps PackageManifestSource) GetDisplayPath() string {
	switch ps.Type {
	case ManifestSourceLocal:
		return filepath.Join(ps.Namespace, ps.Path)
	case ManifestSourcePurl:
		return filepath.Join(ps.Namespace, ps.Path)
	default:
		return ps.DisplayPath
	}
}

func (ps PackageManifestSource) GetNamespace() string {
	return ps.Namespace
}

func (ps PackageManifestSource) GetPath() string {
	return ps.Path
}

func (ps PackageManifestSource) GetType() ManifestSourceType {
	return ps.Type
}

// Represents a package manifest that contains a list
// of packages. Example: pom.xml, requirements.txt
type PackageManifest struct {
	// The source of the package manifest
	Source PackageManifestSource `json:"source"`

	// Filesystem path of this manifest
	Path string `json:"path"`

	// Ecosystem to interpret this manifest
	Ecosystem string `json:"ecosystem"`

	// List of packages obtained by parsing the manifest
	Packages []*Package `json:"packages"`

	// The package dependency graph representation
	DependencyGraph *DependencyGraph[*Package] `json:"dependency_graph"`

	// Lock to serialize updating packages
	m sync.Mutex
}

// Deprecated: Use NewPackageManifest* initializers
func NewPackageManifest(path, ecosystem string) *PackageManifest {
	return NewPackageManifestFromLocal(path, ecosystem)
}

func NewPackageManifestFromLocal(path, ecosystem string) *PackageManifest {
	return newPackageManifest(PackageManifestSource{
		Type:      ManifestSourceLocal,
		Namespace: filepath.Dir(path),
		Path:      filepath.Base(path),
	}, path, ecosystem)
}

func NewPackageManifestFromPurl(purl, ecosystem string) *PackageManifest {
	return newPackageManifest(PackageManifestSource{
		Type:      ManifestSourcePurl,
		Namespace: filepath.Dir(purl),
		Path:      filepath.Base(purl),
	}, purl, ecosystem)
}

func NewPackageManifestFromGitHub(repo, repoRelativePath, realPath, ecosystem string) *PackageManifest {
	return newPackageManifest(PackageManifestSource{
		Type:      ManifestSourceGitRepository,
		Namespace: repo,
		Path:      repoRelativePath,
	}, realPath, ecosystem)
}

func newPackageManifest(source PackageManifestSource, path, ecosystem string) *PackageManifest {
	return &PackageManifest{
		Source:          source,
		Path:            path,
		Ecosystem:       ecosystem,
		Packages:        make([]*Package, 0),
		DependencyGraph: NewDependencyGraph[*Package](),
	}
}

// Parsers usually create a package manifest from file, readers
// have the context to set the source correct. Example: GitHub reader
func (p *PackageManifest) UpdateSourceAsGitRepository(repo, repoRelativePath string) {
	p.Source = PackageManifestSource{
		Type:      ManifestSourceGitRepository,
		Namespace: repo,
		Path:      repoRelativePath,
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

func (pm *PackageManifest) GetSource() PackageManifestSource {
	return pm.Source
}

func (pm *PackageManifest) GetPath() string {
	return pm.Path
}

func (pm *PackageManifest) SetPath(path string) {
	pm.Path = path
}

func (pm *PackageManifest) SetDisplayPath(path string) {
	pm.Source.DisplayPath = path
}

// GetDisplayPath returns the [DisplayPath] if available or fallsback
// to [Path]
func (pm *PackageManifest) GetDisplayPath() string {
	return pm.Source.GetDisplayPath()
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
	case EcosystemRubyGems:
		return packagev1.Ecosystem_ECOSYSTEM_RUBYGEMS
	case EcosystemPyPI:
		return packagev1.Ecosystem_ECOSYSTEM_PYPI
	case EcosystemGitHubActions:
		return packagev1.Ecosystem_ECOSYSTEM_GITHUB_ACTIONS
	case EcosystemPackagist:
		return packagev1.Ecosystem_ECOSYSTEM_PACKAGIST
	case EcosystemTerraform:
		return packagev1.Ecosystem_ECOSYSTEM_TERRAFORM
	case EcosystemTerraformModule:
		return packagev1.Ecosystem_ECOSYSTEM_TERRAFORM_MODULE
	case EcosystemTerraformProvider:
		return packagev1.Ecosystem_ECOSYSTEM_TERRAFORM_PROVIDER
	default:
		return packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED
	}
}

// Deprecated: Move towards GetControlTowerSpecEcosystem
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

// Map the control tower spec ecosystem to model ecosystem
func GetModelEcosystem(ecosystem packagev1.Ecosystem) string {
	switch ecosystem {
	case packagev1.Ecosystem_ECOSYSTEM_GO:
		return EcosystemGo
	case packagev1.Ecosystem_ECOSYSTEM_MAVEN:
		return EcosystemMaven
	case packagev1.Ecosystem_ECOSYSTEM_NPM:
		return EcosystemNpm
	case packagev1.Ecosystem_ECOSYSTEM_PYPI:
		return EcosystemPyPI
	case packagev1.Ecosystem_ECOSYSTEM_RUBYGEMS:
		return EcosystemRubyGems
	case packagev1.Ecosystem_ECOSYSTEM_PACKAGIST:
		return EcosystemPackagist
	case packagev1.Ecosystem_ECOSYSTEM_CARGO:
		return EcosystemCargo
	case packagev1.Ecosystem_ECOSYSTEM_GITHUB_ACTIONS:
		return EcosystemGitHubActions
	case packagev1.Ecosystem_ECOSYSTEM_TERRAFORM_MODULE:
		return EcosystemTerraformModule
	case packagev1.Ecosystem_ECOSYSTEM_TERRAFORM_PROVIDER:
		return EcosystemTerraformProvider
	default:
		return "unknown"
	}
}

type ProvenanceType string

const (
	ProvenanceTypeSlsa = ProvenanceType("slsa")
)

// Represents an abstract provenance of a package provided
// by different sources such as deps.dev or other sources
type Provenance struct {
	Type             ProvenanceType `json:"type"`
	CommitSHA        string         `json:"commit_sha"`
	SourceRepository string         `json:"source_url"`
	Url              string         `json:"url"`
	Verified         bool           `json:"verified"`
}

// Malware analysis results for a given package
type MalwareAnalysisResult struct {
	// The analysis id for this package received from the malware analysis service
	AnalysisId string `json:"analysis_id"`

	// Decision if this package is potentially risky but not enough confidence
	// to classify as malware
	IsSuspicious bool `json:"is_suspicious"`

	// Decision if this package is malware based on analysis data and policy
	IsMalware bool `json:"is_malware"`

	// The report generated by the malware analysis service
	Report *malysisv1.Report `json:"report"`

	// Verification record for the malware analysis
	VerificationRecord *malysisv1.VerificationRecord
}

// Represents a package such as a version of a library defined as a dependency
// in Gemfile.lock, pom.xml etc.
type Package struct {
	lockfile.PackageDetails `json:"package_detail"`

	// Insights obtained for this package
	Insights *insightapi.PackageVersionInsight `json:"insights,omitempty"`

	// Insights v2
	InsightsV2 *packagev1.PackageVersionInsight `json:"insights_v2,omitempty"`

	// This package is a transitive dependency of parent package
	Parent *Package `json:"-"`

	// Depth of this package in dependency tree
	Depth int `json:"depth"`

	// Optional provenances for this package
	Provenances []*Provenance `json:"provenances"`

	// Optional malware analysis result for this package
	MalwareAnalysis *MalwareAnalysisResult `json:"malware_analysis"`

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

func (p *Package) GetControlTowerSpecEcosystem() packagev1.Ecosystem {
	return p.Manifest.GetControlTowerSpecEcosystem()
}

func (p *Package) GetName() string {
	return p.Name
}

func (p *Package) GetVersion() string {
	return p.Version
}

func (p *Package) GetProvenances() []*Provenance {
	return p.Provenances
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

func (p *Package) SetMalwareAnalysisResult(result *MalwareAnalysisResult) {
	p.MalwareAnalysis = result
}

func (p *Package) GetMalwareAnalysisResult() *MalwareAnalysisResult {
	return p.MalwareAnalysis
}

func (p *Package) IsMalware() bool {
	if p.MalwareAnalysis == nil {
		return false
	}

	return p.MalwareAnalysis.IsMalware
}

func (p *Package) IsSuspicious() bool {
	if p.MalwareAnalysis == nil {
		return false
	}

	return p.MalwareAnalysis.IsSuspicious
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
