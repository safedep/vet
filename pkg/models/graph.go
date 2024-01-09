package models

import "encoding/json"

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
}

// Directed Acyclic Graph (DAG) representation of the package manifest
type DependencyGraph[T DependencyGraphNodeType] struct {
	present bool
	nodes   map[string]*DependencyGraphNode[T]
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

// AddDependency adds a dependency from one package to another
// Add an edge from [from] to [to]
func (dg *DependencyGraph[T]) AddDependency(from, to T) {
	if _, ok := dg.nodes[from.Id()]; !ok {
		dg.nodes[from.Id()] = &DependencyGraphNode[T]{Data: from, Children: []T{}}
	}

	if _, ok := dg.nodes[to.Id()]; !ok {
		dg.nodes[to.Id()] = &DependencyGraphNode[T]{Data: to, Children: []T{}}
	}

	dg.nodes[from.Id()].Children = append(dg.nodes[from.Id()].Children, dg.nodes[to.Id()].Data)
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
// This is useful when enumerating all packages
func (dg *DependencyGraph[T]) GetNodes() []T {
	var nodes []T
	for _, node := range dg.nodes {
		nodes = append(nodes, node.Data)
	}

	return nodes
}

// Alias for GetNodes
func (dg *DependencyGraph[T]) GetPackages() []T {
	return dg.GetNodes()
}

// PathToRoot returns the path from the given package to the root
// It uses a simple DFS algorithm to find the path. In future, it is likely
// that we will use a more efficient algorithm like a weighted traversal which
// is more relevant here because we want to update minimum number of root packages
func (dg *DependencyGraph[T]) PathToRoot(pkg T) []T {
	var path []T
	for _, node := range dg.nodes {
		if node.Data.Id() == pkg.Id() {
			path = append(path, node.Data)
			break
		}
	}

	for len(path) > 0 {
		node := path[len(path)-1]
		dependents := dg.GetDependents(node)
		if len(dependents) == 0 {
			break
		}

		path = append(path, dependents[0])
	}

	return path
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
