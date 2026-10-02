// Package graph sets the parent ids of the packages of a lockfile.
package graph

import (
	"maps"
	"slices"

	"github.com/google/osv-scalibr/binary/proto/metadata"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
)

// Metadata wraps the metadata of a package and records that the root
// project requires the package. The scalibr adapter reads IsDirect.
type Metadata struct {
	metadata.Protoable
	Direct bool
}

// IsDirect reports that the root project requires the package.
func (m *Metadata) IsDirect() bool { return m.Direct }

// DepGroups returns the dependency groups of the wrapped metadata.
func (m *Metadata) DepGroups() []string {
	if dg, ok := m.Protoable.(osv.DepGroups); ok {
		return dg.DepGroups()
	}
	return nil
}

// Link sets the parent ids of each package. keys[i] is the lockfile key of
// pkgs[i], for example "name@version". parents maps the key of a child to
// the keys of its parents. A parent key with no package is skipped, so the
// root project of a lockfile, which is not a package, makes no edge. Each
// package with a key in direct gets Metadata with Direct set.
func Link(pkgs []*extractor.Package, keys []string, parents map[string]map[string]bool, direct map[string]bool) error {
	ids := make(map[string]string, len(pkgs))
	for i, p := range pkgs {
		id, err := p.RequireID()
		if err != nil {
			return err
		}
		ids[keys[i]] = id
	}
	for i, p := range pkgs {
		if direct[keys[i]] {
			p.Metadata = &Metadata{Protoable: p.Metadata, Direct: true}
		}
		for _, pk := range slices.Sorted(maps.Keys(parents[keys[i]])) {
			pid, ok := ids[pk]
			if !ok || pid == p.ID {
				continue
			}
			if p.ParentIDs == nil {
				p.ParentIDs = map[string]bool{}
			}
			p.ParentIDs[pid] = true
		}
	}
	return nil
}

// Add records that parent requires child.
func Add(parents map[string]map[string]bool, child, parent string) {
	if parents[child] == nil {
		parents[child] = map[string]bool{}
	}
	parents[child][parent] = true
}
