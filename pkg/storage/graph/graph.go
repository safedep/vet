package graph

import (
	"context"
)

// A node in a property graph
type Node struct {
	// Unique ID for the node.
	// The consumer of the graph is responsible for ensuring uniqueness.
	ID string

	// Label for the node. This is usually the type of the node.
	// In a quad store, this would be the context of the quad.
	Label string

	// Properties for the node.
	Properties map[string]string
}

// An edge in a property graph
type Edge struct {
	// Identifier for the type of relationship.
	Name string

	// The label for the edge. This is usually the type of the edge.
	// In a quad store, this would be the context of the quad.
	Label string

	// Properties for the edge.
	Properties map[string]string

	// The node the edge is coming from.
	From *Node

	// The node the edge is going to.
	To *Node
}

// The result of a query on the graph. The results depends
// on the implementation specific query executed on the graph
type QueryResult interface {
	// Return the results as a slice of strings
	Strings() ([]string, error)

	// Return the results as list of nodes
	// that matches a path query
	Nodes() ([]Node, error)
}

type Graph interface {
	// Create a link in the graph between two Node using the Edge
	Link(link *Edge) error

	// Query the graph using an implementation-specific query language
	Query(ctx context.Context, query string) (QueryResult, error)

	// Close the graph
	Close() error
}

// Configuration for property graph implementations that
// uses local file system as the storage
type LocalPropertyGraphConfig struct {
	Name         string
	DatabasePath string
	OpenExisting bool
}
