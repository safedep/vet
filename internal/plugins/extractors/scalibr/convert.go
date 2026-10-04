package scalibr

import (
	"cmp"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"

	"github.com/safedep/vet/v2/model"
)

// Converted is the output of one extractor on one file.
type Converted struct {
	// Path is the manifest path relative to the target root, with "/".
	Path string
	// Extractor is the name of the Scalibr extractor.
	Extractor string
	// Root is the file system of the target.
	Root      fs.FS
	Inventory inventory.Inventory
}

// direct is the metadata of a vet extractor that knows the direct
// dependencies of a lockfile.
type direct interface{ IsDirect() bool }

// lockEntry is the metadata of a vet lockfile extractor that knows the URL
// and the integrity hash of an entry.
type lockEntry interface {
	Resolved() string
	Integrity() string
	Local() bool
}

// ToManifest converts the packages of one extractor run into a manifest.
// It returns the manifest, or nil when the run found no package that vet
// knows, and one error for each package that it skipped. A workflow is a
// manifest even with no package, because the workflow controls read the
// file itself. A package with an
// ecosystem outside the vet ecosystem table is skipped, because no
// enricher has data for it.
func ToManifest(in Converted) (*model.Manifest, []error) {
	kind := kindOf(in.Extractor)
	fileOnly := kind == model.ManifestKindWorkflow || kind == model.ManifestKindAgentConfig
	if len(in.Inventory.Packages) == 0 && !fileOnly {
		return nil, nil
	}
	m := &model.Manifest{
		ID:        model.ManifestID(in.Path, in.Extractor),
		Path:      in.Path,
		Kind:      kind,
		Extractor: in.Extractor,
		Root:      in.Root,
	}

	var errs []error
	byScalibrID := map[string]model.PackageVersion{}
	seen := map[model.PackageKey]*model.Package{}
	hasEdges := false
	for _, sp := range in.Inventory.Packages {
		if localGoReplacement(sp) {
			continue
		}
		p, err := toPackage(sp)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", in.Path, err))
			continue
		}
		if sp.ID != "" {
			byScalibrID[sp.ID] = p.ID
		}
		hasEdges = hasEdges || len(sp.ParentIDs) > 0
		if prev, dup := seen[p.ID.Key()]; dup {
			prev.Direct = prev.Direct || p.Direct
			prev.Dev = prev.Dev && p.Dev
			continue
		}
		seen[p.ID.Key()] = p
		m.Packages = append(m.Packages, p)
	}
	if len(m.Packages) == 0 {
		if kind == model.ManifestKindWorkflow {
			m.Ecosystem = model.EcosystemGitHubActions
		}
		if fileOnly {
			return m, errs
		}
		return nil, errs
	}
	m.Ecosystem = mainEcosystem(m.Packages)
	slices.SortStableFunc(m.Packages, func(a, b *model.Package) int {
		if c := cmp.Compare(a.Line, b.Line); c != 0 {
			return c
		}
		return cmp.Compare(a.ID.Key(), b.ID.Key())
	})

	switch {
	case hasEdges:
		m.Graph = graphOf(in.Inventory.Packages, byScalibrID, seen)
	case m.Kind != model.ManifestKindLockfile:
		// A manifest declares only its direct dependencies.
		for _, p := range m.Packages {
			p.Direct = true
		}
	}
	return m, errs
}

// mainEcosystem returns the ecosystem of most packages. An SBOM can mix
// ecosystems. A tie picks the first name in order, so the result does not
// depend on the order of the packages.
func mainEcosystem(pkgs []*model.Package) model.Ecosystem {
	counts := map[model.Ecosystem]int{}
	for _, p := range pkgs {
		counts[p.ID.Ecosystem()]++
	}
	var best model.Ecosystem
	for _, e := range slices.Sorted(maps.Keys(counts)) {
		if counts[e] > counts[best] {
			best = e
		}
	}
	return best
}

// localGoReplacement reports a go.mod replace target on the local disk, as
// in replace example.com/x => ../x. It is code of the project, not a
// module, and it has no PURL.
func localGoReplacement(sp *extractor.Package) bool {
	return sp.PURLType == purl.TypeGolang && sp.Version == "" &&
		(strings.HasPrefix(sp.Name, ".") || strings.HasPrefix(sp.Name, "/") || filepath.IsAbs(sp.Name))
}

func toPackage(sp *extractor.Package) (*model.Package, error) {
	pu := sp.PURL()
	if pu == nil {
		return nil, fmt.Errorf("package %s@%s has no PURL", sp.Name, sp.Version)
	}
	fromPURL, err := model.ParsePURL(pu.String())
	if err != nil {
		return nil, err
	}
	version := cmp.Or(sp.Version, fromPURL.RawVersion())
	id, err := model.NewPackageVersion(fromPURL.Ecosystem(), rawName(sp.Name, fromPURL.RawName()), version)
	if err != nil {
		return nil, err
	}
	p := &model.Package{ID: id}
	if loc := sp.Location.Descriptor; loc != nil && loc.File != nil {
		p.Line = loc.File.LineNumber
	}
	if dg, ok := sp.Metadata.(osv.DepGroups); ok {
		groups := dg.DepGroups()
		p.Dev = len(groups) > 0 && !slices.ContainsFunc(groups, isProdGroup)
	}
	if e, ok := sp.Metadata.(lockEntry); ok {
		p.Resolved, p.Integrity, p.Local = e.Resolved(), e.Integrity(), e.Local()
	}
	if d, ok := sp.Metadata.(direct); ok {
		p.Direct = d.IsDirect()
	}
	return p, nil
}

// isProdGroup reports a dependency group that ships with the package.
func isProdGroup(g string) bool {
	switch strings.ToLower(g) {
	case "dev", "development", "test", "tests":
		return false
	}
	return true
}

// graphOf builds the graph from the parent ids. A root is a direct
// dependency: a package that the extractor marks direct, or a package with
// no parent.
func graphOf(pkgs []*extractor.Package, byScalibrID map[string]model.PackageVersion, seen map[model.PackageKey]*model.Package) *model.Graph {
	g := model.NewGraph()
	for _, sp := range pkgs {
		child, ok := byScalibrID[sp.ID]
		if !ok {
			continue
		}
		parents := 0
		for _, pid := range slices.Sorted(maps.Keys(sp.ParentIDs)) {
			if parent, ok := byScalibrID[pid]; ok && !parent.Equal(child) {
				g.AddEdge(parent, child)
				parents++
			}
		}
		if parents == 0 || seen[child.Key()].Direct {
			g.AddRoot(child)
			seen[child.Key()].Direct = true
		}
	}
	return g
}

// rawName returns the name as the manifest writes it. Scalibr builds its
// PURL with the packageurl-go fold, which lowers the case of a Go path and
// folds PyPI separators, so the PURL name is not the raw name. The PURL still
// holds the namespace, such as the Maven group, that an SBOM component name
// can leave out. vet takes the extractor name when it differs from the PURL
// name only in case and separators, and the PURL name in all other cases.
func rawName(name, fromPURL string) string {
	if name != "" && looseName(name) == looseName(fromPURL) {
		return name
	}
	return fromPURL
}

var nameSeparators = strings.NewReplacer("_", "-", ".", "-")

func looseName(s string) string { return nameSeparators.Replace(strings.ToLower(s)) }
