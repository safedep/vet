package scalibr

import (
	"cmp"
	"fmt"
	"io/fs"
	"maps"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"

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

// subpath is the metadata of a vet extractor that knows the PURL subpath
// of a package, such as the sub-path of a GitHub action.
type subpath interface{ Subpath() string }

// ToManifest converts the packages of one extractor run into a manifest.
// It returns the manifest, or nil when the run found no package that vet
// knows, and one error for each package that it skipped. A workflow is a
// manifest even with no package, because the workflow controls read the
// file itself. A package with an
// ecosystem outside the vet ecosystem table is skipped, because no
// enricher has data for it.
func ToManifest(in Converted) (*model.Manifest, []error) {
	kind := kindOf(in.Extractor)
	if len(in.Inventory.Packages) == 0 && kind != model.ManifestKindWorkflow {
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
	byScalibrID := map[string]model.PackageID{}
	seen := map[model.PackageID]*model.Package{}
	hasEdges := false
	for _, sp := range in.Inventory.Packages {
		p, err := toPackage(sp)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", in.Path, err))
			continue
		}
		if sp.ID != "" {
			byScalibrID[sp.ID] = p.ID
		}
		hasEdges = hasEdges || len(sp.ParentIDs) > 0
		if prev, dup := seen[p.ID]; dup {
			prev.Direct = prev.Direct || p.Direct
			prev.Dev = prev.Dev && p.Dev
			continue
		}
		seen[p.ID] = p
		m.Packages = append(m.Packages, p)
	}
	if len(m.Packages) == 0 {
		if kind == model.ManifestKindWorkflow {
			m.Ecosystem = model.EcosystemGitHubActions
			return m, errs
		}
		return nil, errs
	}
	m.Ecosystem = mainEcosystem(m.Packages)
	slices.SortStableFunc(m.Packages, func(a, b *model.Package) int {
		if c := cmp.Compare(a.Line, b.Line); c != 0 {
			return c
		}
		return cmp.Compare(a.ID.PURL(), b.ID.PURL())
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
		counts[p.ID.Ecosystem]++
	}
	var best model.Ecosystem
	for _, e := range slices.Sorted(maps.Keys(counts)) {
		if counts[e] > counts[best] {
			best = e
		}
	}
	return best
}

func toPackage(sp *extractor.Package) (*model.Package, error) {
	pu := sp.PURL()
	if pu == nil {
		return nil, fmt.Errorf("package %s@%s has no PURL", sp.Name, sp.Version)
	}
	id, err := model.ParsePURL(pu.String())
	if err != nil {
		return nil, err
	}
	if md, ok := sp.Metadata.(subpath); ok {
		id.Subpath = md.Subpath()
	}
	if id.Ecosystem == model.EcosystemGo {
		id.Namespace, id.Name = splitGoPath(sp.Name)
	}
	p := &model.Package{ID: id}
	if loc := sp.Location.Descriptor; loc != nil && loc.File != nil {
		p.Line = loc.File.LineNumber
	}
	if dg, ok := sp.Metadata.(osv.DepGroups); ok {
		groups := dg.DepGroups()
		p.Dev = len(groups) > 0 && !slices.ContainsFunc(groups, isProdGroup)
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
func graphOf(pkgs []*extractor.Package, byScalibrID map[string]model.PackageID, seen map[model.PackageID]*model.Package) *model.Graph {
	g := model.NewGraph()
	for _, sp := range pkgs {
		child, ok := byScalibrID[sp.ID]
		if !ok {
			continue
		}
		parents := 0
		for _, pid := range slices.Sorted(maps.Keys(sp.ParentIDs)) {
			if parent, ok := byScalibrID[pid]; ok && parent != child {
				g.AddEdge(parent, child)
				parents++
			}
		}
		if parents == 0 || seen[child].Direct {
			g.AddRoot(child)
			seen[child].Direct = true
		}
	}
	return g
}

// splitGoPath splits a Go module path into the PURL namespace and name. A
// golang PURL is in lower case, but Go module paths are case sensitive, so
// vet keeps the path that the manifest declares.
func splitGoPath(path string) (string, string) {
	i := strings.LastIndex(path, "/")
	if i < 0 {
		return "", path
	}
	return path[:i], path[i+1:]
}
