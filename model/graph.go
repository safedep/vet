package model

import "sort"

// Graph is the dependency graph of one manifest. Roots are the direct
// dependencies.
type Graph struct {
	roots map[PackageID]struct{}
	edges map[PackageID]map[PackageID]struct{}
}

// NewGraph returns an empty graph.
func NewGraph() *Graph {
	return &Graph{
		roots: map[PackageID]struct{}{},
		edges: map[PackageID]map[PackageID]struct{}{},
	}
}

// AddRoot marks a package as a direct dependency.
func (g *Graph) AddRoot(id PackageID) {
	g.roots[id] = struct{}{}
}

// AddEdge records that parent depends on child.
func (g *Graph) AddEdge(parent, child PackageID) {
	children, ok := g.edges[parent]
	if !ok {
		children = map[PackageID]struct{}{}
		g.edges[parent] = children
	}
	children[child] = struct{}{}
}

// Roots returns the direct dependencies, sorted.
func (g *Graph) Roots() []PackageID {
	return sortedIDs(g.roots)
}

// Children returns the dependencies of a package, sorted.
func (g *Graph) Children(id PackageID) []PackageID {
	return sortedIDs(g.edges[id])
}

// Parents returns the packages that depend on a package, sorted.
func (g *Graph) Parents(id PackageID) []PackageID {
	set := map[PackageID]struct{}{}
	for parent, children := range g.edges {
		if _, ok := children[id]; ok {
			set[parent] = struct{}{}
		}
	}
	return sortedIDs(set)
}

// Edges calls fn for each edge in a stable order.
func (g *Graph) Edges(fn func(parent, child PackageID)) {
	parents := make(map[PackageID]struct{}, len(g.edges))
	for p := range g.edges {
		parents[p] = struct{}{}
	}
	for _, p := range sortedIDs(parents) {
		for _, c := range g.Children(p) {
			fn(p, c)
		}
	}
}

// PathTo returns one shortest path from a root to the package, or nil when
// the package is not reachable.
func (g *Graph) PathTo(id PackageID) []PackageID {
	type node struct {
		id   PackageID
		prev *node
	}
	seen := map[PackageID]bool{}
	queue := make([]*node, 0, len(g.roots))
	for _, r := range g.Roots() {
		seen[r] = true
		queue = append(queue, &node{id: r})
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if n.id == id {
			var path []PackageID
			for c := n; c != nil; c = c.prev {
				path = append([]PackageID{c.id}, path...)
			}
			return path
		}
		for _, c := range g.Children(n.id) {
			if !seen[c] {
				seen[c] = true
				queue = append(queue, &node{id: c, prev: n})
			}
		}
	}
	return nil
}

func sortedIDs(set map[PackageID]struct{}) []PackageID {
	out := make([]PackageID, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].String() < out[j].String() })
	return out
}
