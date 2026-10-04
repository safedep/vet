package model

import "sort"

// Graph is the dependency graph of one manifest. Roots are the direct
// dependencies. It keys each node by PackageKey, so two spellings of one
// package version are one node.
type Graph struct {
	nodes map[PackageKey]PackageVersion
	roots map[PackageKey]struct{}
	edges map[PackageKey]map[PackageKey]struct{}
}

// NewGraph returns an empty graph.
func NewGraph() *Graph {
	return &Graph{
		nodes: map[PackageKey]PackageVersion{},
		roots: map[PackageKey]struct{}{},
		edges: map[PackageKey]map[PackageKey]struct{}{},
	}
}

// AddRoot marks a package as a direct dependency.
func (g *Graph) AddRoot(id PackageVersion) {
	g.roots[g.node(id)] = struct{}{}
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

// sorted returns the nodes of a key set in a stable order.
func (g *Graph) sorted(set map[PackageKey]struct{}) []PackageVersion {
	keys := make([]PackageKey, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	out := make([]PackageVersion, len(keys))
	for i, k := range keys {
		out[i] = g.nodes[k]
	}
	return out
}
