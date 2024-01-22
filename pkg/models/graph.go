package models

import (
	"cmp"
	"encoding/json"
	"slices"
)

// We are using generics here to make the graph implementation
// not too coupled with our model types
type DependencyGraphNodeType interface {
	Id() string
}

// DependencyGraphNode represents a node in the dependency graph. It must be
// serializable to JSON
type DependencyGraphNode[T DependencyGraphNodeType] struct {
	Data     T   `json:"data"`
	Children []T `json:"children"`

	// While not relevant for a graph, this is required to identify root packages
	Root bool `json:"root"`
}

// Directed Acyclic Graph (DAG) representation of the package manifest
type DependencyGraph[T DependencyGraphNodeType] struct {
	present bool
	nodes   map[string]*DependencyGraphNode[T]
}

func (node *DependencyGraphNode[T]) SetRoot(root bool) {
	node.Root = root
}

func NewDependencyGraph[T DependencyGraphNodeType]() *DependencyGraph[T] {
	return &DependencyGraph[T]{
		present: false,
		nodes:   make(map[string]*DependencyGraphNode[T]),
	}
}

// Present returns true if the dependency graph is present
func (dg *DependencyGraph[T]) Present() bool {
	return dg.present
}

// Clear clears the dependency graph
func (dg *DependencyGraph[T]) Clear() {
	dg.present = false
	dg.nodes = make(map[string]*DependencyGraphNode[T])
}

// Set present flag for the dependency graph
// This is useful when we want to indicate that the graph is present
// because we are building it as an enhancement over our existing list of packages
func (dg *DependencyGraph[T]) SetPresent(present bool) {
	dg.present = present
}

// Add a node to the graph
func (dg *DependencyGraph[T]) AddNode(node T) {
	_ = dg.findOrCreateNode(node)
}

func (dg *DependencyGraph[T]) IsRoot(data T) bool {
	if node, ok := dg.nodes[data.Id()]; ok {
		return node.Root
	}

	return false
}

// Add a root node to the graph
func (dg *DependencyGraph[T]) AddRootNode(node T) {
	dg.AddNode(node)
	dg.nodes[node.Id()].Root = true
}

// AddDependency adds a dependency from one package to another
// Add an edge from [from] to [to]
func (dg *DependencyGraph[T]) AddDependency(from, to T) {
	fromNode := dg.findOrCreateNode(from)
	toNode := dg.findOrCreateNode(to)

	fromNode.Children = append(fromNode.Children, toNode.Data)
}

// GetDependencies returns the list of dependencies for the given package
// Outgoing edges
func (dg *DependencyGraph[T]) GetDependencies(pkg T) []T {
	if _, ok := dg.nodes[pkg.Id()]; !ok {
		return []T{}
	}

	return dg.nodes[pkg.Id()].Children
}

// GetDependents returns the list of dependents for the given package
// Incoming edges
func (dg *DependencyGraph[T]) GetDependents(pkg T) []T {
	if _, ok := dg.nodes[pkg.Id()]; !ok {
		return []T{}
	}

	dependents := []T{}
	for _, node := range dg.nodes {
		for _, child := range node.Children {
			if child.Id() == pkg.Id() {
				dependents = append(dependents, node.Data)
			}
		}
	}

	return dependents
}

// GetNodes returns the list of nodes in the graph
func (dg *DependencyGraph[T]) GetNodes() []*DependencyGraphNode[T] {
	var nodes []*DependencyGraphNode[T]
	for _, node := range dg.nodes {
		nodes = append(nodes, node)
	}

	return nodes
}

// GetPackages returns the list of packages in the graph
func (dg *DependencyGraph[T]) GetPackages() []T {
	var packages []T
	for _, node := range dg.nodes {
		packages = append(packages, node.Data)
	}

	return packages
}

// PathToRoot returns the path from the given package to the root
// It uses a simple DFS algorithm to find the path. In future, it is likely
// that we will use a more efficient algorithm like a weighted traversal which
// is more relevant here because we want to update minimum number of root packages
func (dg *DependencyGraph[T]) PathToRoot(pkg T) []T {
	var path []T

	// If the package is not present in the graph, return an empty path
	if node, ok := dg.nodes[pkg.Id()]; ok {
		path = append(path, node.Data)
	} else {
		return path
	}

	// Check if we are already at the root
	if dg.nodes[pkg.Id()].Root {
		return path
	}

	visited := make(map[string]bool)
	for len(path) > 0 {
		node := path[len(path)-1]
		dependents := dg.GetDependents(node)
		if len(dependents) == 0 {
			break
		}

		// Sort dependents by Id to ensure deterministic traversal
		slices.SortFunc(dependents, func(a, b T) int {
			return cmp.Compare(a.Id(), b.Id())
		})

		progress := false
		for _, dependent := range dependents {
			if _, ok := visited[dependent.Id()]; !ok {
				path = append(path, dependent)
				visited[dependent.Id()] = true
				progress = true
				break
			}
		}

		if !progress {
			break
		}

		if n, ok := dg.nodes[path[len(path)-1].Id()]; ok && n.Root {
			break
		}
	}

	return path
}

func (dg *DependencyGraph[T]) findOrCreateNode(data T) *DependencyGraphNode[T] {
	id := data.Id()
	if _, ok := dg.nodes[id]; !ok {
		dg.nodes[id] = &DependencyGraphNode[T]{
			Root:     false,
			Data:     data,
			Children: []T{},
		}
	}

	return dg.nodes[id]
}

func (dg *DependencyGraph[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(&struct {
		Present bool                               `json:"present"`
		Nodes   map[string]*DependencyGraphNode[T] `json:"nodes"`
	}{
		dg.present,
		dg.nodes,
	})
}

func (dg *DependencyGraph[T]) UnmarshalJSON(b []byte) error {
	var data struct {
		Present bool                               `json:"present"`
		Nodes   map[string]*DependencyGraphNode[T] `json:"nodes"`
	}

	if err := json.Unmarshal(b, &data); err != nil {
		return err
	}

	dg.present = data.Present
	dg.nodes = data.Nodes

	return nil
}
