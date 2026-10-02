// Package graph sets the parent ids of the packages of a lockfile.
package graph

import (
	"maps"
	"slices"

	"github.com/google/osv-scalibr/extractor"
)

// Link sets the parent ids of each package. keys[i] is the lockfile key of
// pkgs[i], for example "name@version". parents maps the key of a child to
// the keys of its parents. A parent key with no package is skipped, so the
// root project of a lockfile, which is not a package, makes no edge.
func Link(pkgs []*extractor.Package, keys []string, parents map[string]map[string]bool) error {
	ids := make(map[string]string, len(pkgs))
	for i, p := range pkgs {
		id, err := p.RequireID()
		if err != nil {
			return err
		}
		ids[keys[i]] = id
	}
	for i, p := range pkgs {
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
