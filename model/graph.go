package model

import (
	"maps"
	"slices"
)

// Graph is the dependency graph of one manifest. Roots are the direct
// dependencies. It keys each node by PackageKey, so two spellings of one
// package version are one node. An open node is a package whose
// dependencies vet does not know, such as a Go module with no source on
// the disk. It may depend on any package. In a graph of imports, as the
// module graph of a go.mod, the roots are the packages that the code of
// the manifest imports and an edge is an import. A test root is a root that
// only the test files of the code import.
type Graph struct {
	nodes     map[PackageKey]PackageVersion
	roots     map[PackageKey]struct{}
	testRoots map[PackageKey]struct{}
	edges     map[PackageKey]map[PackageKey]struct{}
	open      map[PackageKey]struct{}
	imports   bool
}

// NewGraph returns an empty graph.
func NewGraph() *Graph {
	return &Graph{
		nodes:     map[PackageKey]PackageVersion{},
		roots:     map[PackageKey]struct{}{},
		testRoots: map[PackageKey]struct{}{},
		edges:     map[PackageKey]map[PackageKey]struct{}{},
		open:      map[PackageKey]struct{}{},
	}
}

// MarkOpen records that vet does not know the dependencies of a package.
func (g *Graph) MarkOpen(id PackageVersion) {
	g.open[g.node(id)] = struct{}{}
}

// Open returns the open packages, sorted.
func (g *Graph) Open() []PackageVersion {
	return g.sorted(g.open)
}

// SetImports marks a graph of imports.
func (g *Graph) SetImports() { g.imports = true }

// Imports reports a graph of imports.
func (g *Graph) Imports() bool { return g.imports }

// AddRoot marks a package as a direct dependency.
func (g *Graph) AddRoot(id PackageVersion) {
	g.roots[g.node(id)] = struct{}{}
}

// AddTestRoot marks a package as a root that only test files import.
func (g *Graph) AddTestRoot(id PackageVersion) {
	k := g.node(id)
	g.roots[k] = struct{}{}
	g.testRoots[k] = struct{}{}
}

// Root reports whether a package is a root, and whether it is a test root.
func (g *Graph) Root(id PackageVersion) (root, test bool) {
	k := id.Key()
	_, root = g.roots[k]
	_, test = g.testRoots[k]
	return root, test
}

// TestRoots returns the test roots, sorted.
func (g *Graph) TestRoots() []PackageVersion {
	return g.sorted(g.testRoots)
}

// AddEdge records that parent depends on child.
func (g *Graph) AddEdge(parent, child PackageVersion) {
	p, c := g.node(parent), g.node(child)
	children, ok := g.edges[p]
	if !ok {
		children = map[PackageKey]struct{}{}
		g.edges[p] = children
	}
	children[c] = struct{}{}
}

// node keeps the first spelling of a package version and returns its key.
func (g *Graph) node(id PackageVersion) PackageKey {
	k := id.Key()
	if _, ok := g.nodes[k]; !ok {
		g.nodes[k] = id
	}
	return k
}

// Roots returns the direct dependencies, sorted.
func (g *Graph) Roots() []PackageVersion {
	return g.sorted(g.roots)
}

// Children returns the dependencies of a package, sorted.
func (g *Graph) Children(id PackageVersion) []PackageVersion {
	return g.sorted(g.edges[id.Key()])
}

// Parents returns the packages that depend on a package, sorted.
func (g *Graph) Parents(id PackageVersion) []PackageVersion {
	k := id.Key()
	set := map[PackageKey]struct{}{}
	for parent, children := range g.edges {
		if _, ok := children[k]; ok {
			set[parent] = struct{}{}
		}
	}
	return g.sorted(set)
}

// Edges calls fn for each edge in a stable order.
func (g *Graph) Edges(fn func(parent, child PackageVersion)) {
	parents := make(map[PackageKey]struct{}, len(g.edges))
	for p := range g.edges {
		parents[p] = struct{}{}
	}
	for _, p := range g.sorted(parents) {
		for _, c := range g.Children(p) {
			fn(p, c)
		}
	}
}

// PathTo returns one shortest path from a root to the package, or nil when
// the package is not reachable.
func (g *Graph) PathTo(id PackageVersion) []PackageVersion {
	type node struct {
		key  PackageKey
		prev *node
	}
	target := id.Key()
	seen := map[PackageKey]bool{}
	queue := make([]*node, 0, len(g.roots))
	for _, r := range g.Roots() {
		seen[r.Key()] = true
		queue = append(queue, &node{key: r.Key()})
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if n.key == target {
			var path []PackageVersion
			for c := n; c != nil; c = c.prev {
				path = append([]PackageVersion{g.nodes[c.key]}, path...)
			}
			return path
		}
		for c := range g.edges[n.key] {
			if !seen[c] {
				seen[c] = true
				queue = append(queue, &node{key: c, prev: n})
			}
		}
	}
	return nil
}

// PathFrom returns one shortest path from a package of from to the
// package, or nil when none of them reaches it. The search visits the
// sources and the children in key order, so each call gives the same path.
func (g *Graph) PathFrom(from []PackageVersion, id PackageVersion) []PackageVersion {
	target := id.Key()
	prev := map[PackageKey]PackageKey{}
	var queue []PackageKey
	starts := make([]PackageKey, 0, len(from))
	for _, f := range from {
		starts = append(starts, f.Key())
	}
	slices.Sort(starts)
	for _, k := range starts {
		if _, ok := g.nodes[k]; ok {
			if _, seen := prev[k]; !seen {
				prev[k] = k
				queue = append(queue, k)
			}
		}
	}
	for len(queue) > 0 {
		k := queue[0]
		queue = queue[1:]
		if k == target {
			path := []PackageVersion{g.nodes[k]}
			for prev[k] != k {
				k = prev[k]
				path = append(path, g.nodes[k])
			}
			slices.Reverse(path)
			return path
		}
		for _, c := range g.sortedKeys(g.edges[k]) {
			if _, seen := prev[c]; !seen {
				prev[c] = k
				queue = append(queue, c)
			}
		}
	}
	return nil
}

// MayReach reports whether a package of from can depend on the package: a
// path of known edges reaches it, or a path meets an open package, which
// may depend on any package. PathFrom gives only the paths of known edges.
func (g *Graph) MayReach(from []PackageVersion, id PackageVersion) bool {
	target := id.Key()
	seen := map[PackageKey]bool{}
	var queue []PackageKey
	for _, f := range from {
		if k := f.Key(); !seen[k] {
			seen[k] = true
			queue = append(queue, k)
		}
	}
	for len(queue) > 0 {
		k := queue[0]
		queue = queue[1:]
		if _, open := g.open[k]; open || k == target {
			return true
		}
		for c := range g.edges[k] {
			if !seen[c] {
				seen[c] = true
				queue = append(queue, c)
			}
		}
	}
	return false
}

func (g *Graph) sortedKeys(set map[PackageKey]struct{}) []PackageKey {
	return slices.Sorted(maps.Keys(set))
}

// sorted returns the nodes of a key set in a stable order.
func (g *Graph) sorted(set map[PackageKey]struct{}) []PackageVersion {
	keys := g.sortedKeys(set)
	out := make([]PackageVersion, len(keys))
	for i, k := range keys {
		out[i] = g.nodes[k]
	}
	return out
}
