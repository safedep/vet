package graph

import (
	"context"
	"fmt"

	_ "github.com/cayleygraph/cayley/graph/kv/bolt"

	"github.com/cayleygraph/cayley"
	"github.com/cayleygraph/cayley/graph"
	"github.com/cayleygraph/cayley/query"
	"github.com/cayleygraph/cayley/query/gizmo"
	"github.com/cayleygraph/quad"
)

const (
	quadGraphVersion    = "1.0.0"
	internalMetaContext = "internal_meta"
	queryMaxLimit       = 10000
)

type cayleyGraph struct {
	store             *cayley.Handle
	config            *LocalPropertyGraphConfig
	gizmoQuerySession *gizmo.Session
}

func NewInMemoryPropertyGraph(config *LocalPropertyGraphConfig) (Graph, error) {
	store, err := cayley.NewMemoryGraph()
	if err != nil {
		return nil, err
	}

	return buildCayleyGraph(config, store)
}

func NewPropertyGraph(config *LocalPropertyGraphConfig) (Graph, error) {
	var err error

	if !config.OpenExisting {
		err = graph.InitQuadStore("bolt", config.DatabasePath, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize quad store: %v", err)
		}
	}

	// Placeholder for future options
	options := graph.Options{}

	store, err := cayley.NewGraph("bolt", config.DatabasePath, options)
	if err != nil {
		return nil, fmt.Errorf("failed to create graph: %v", err)
	}

	return buildCayleyGraph(config, store)
}

func buildCayleyGraph(config *LocalPropertyGraphConfig, store *cayley.Handle) (*cayleyGraph, error) {
	err := store.AddQuad(quad.Make("_graph", "version", quadGraphVersion, internalMetaContext))
	if err != nil {
		return nil, fmt.Errorf("failed to add graph version: %v", err)
	}

	return &cayleyGraph{
		config: config,
		store:  store,
	}, nil
}

// Create the data model in the graph by linking nodes, properties
// and edges
func (g *cayleyGraph) Link(link *Edge) error {
	err := g.addNodeProperties(link.From)
	if err != nil {
		return err
	}

	err = g.addNodeProperties(link.To)
	if err != nil {
		return err
	}

	edge := quad.Make(link.From.ID, link.Name, link.To.ID, link.Label)
	err = g.store.AddQuad(edge)
	if err != nil {
		return err
	}

	for key, value := range link.Properties {
		err = g.store.AddQuad(quad.Make(edge, key, value, link.Label))
		if err != nil {
			return err
		}
	}

	return nil
}

type cayleyQueryResult struct {
	store   *cayley.Handle
	results []*gizmo.Result
}

func (q *cayleyQueryResult) Strings() ([]string, error) {
	res := []string{}
	for _, r := range q.results {
		if r.Val == nil {
			for _, ref := range r.Tags {
				if ref == nil {
					continue
				}

				n, err := q.store.NameOf(ref)
				if (err != nil) || (n == nil) {
					continue
				}

				// https://github.com/cayleygraph/cayley/blob/master/query/gizmo/finals.go#L205
				if s, ok := n.(quad.String); ok {
					res = append(res, string(s))
				} else {
					res = append(res, quad.StringOf(n))
				}

			}
		} else {
			s, ok := r.Val.(string)
			if !ok {
				return nil, fmt.Errorf("unexpected result type: %T", r.Result)
			}

			res = append(res, s)

		}
	}

	return res, nil
}

// Reconstruct the nodes from the query results
func (q *cayleyQueryResult) Nodes() ([]Node, error) {
	nodes := []Node{}
	for _, r := range q.results {
		if r.Val == nil {
			node := Node{Properties: map[string]string{}}
			for tag, ref := range r.Tags {
				if ref == nil {
					continue
				}

				n, err := q.store.NameOf(ref)
				if (err != nil) || (n == nil) {
					continue
				}

				node.Properties[tag] = quad.StringOf(n)
			}
		} else {
			if s, ok := r.Val.(string); ok {
				node := Node{ID: s}
				nodes = append(nodes, node)
			} else {
				return nil, fmt.Errorf("unexpected result type: %T", r.Val)
			}
		}
	}

	return nodes, nil
}

// Query using Gizmo API
// https://cayley.gitbook.io/cayley/query-languages/gizmoapi
func (g *cayleyGraph) Query(ctx context.Context, q string) (QueryResult, error) {
	session := g.querySession()

	it, err := session.Execute(ctx, q, query.Options{
		Collation: query.Raw,
		Limit:     queryMaxLimit,
	})
	if err != nil {
		return nil, err
	}

	defer it.Close()

	qs := &cayleyQueryResult{store: g.store}
	for it.Next(ctx) {
		err := it.Err()
		if err != nil {
			break
		}

		// https://github.com/cayleygraph/cayley/blob/master/query/gizmo/gizmo_test.go#L710
		data, ok := it.Result().(*gizmo.Result)
		if !ok {
			return nil, fmt.Errorf("unexpected result type: %T", it.Result())
		}

		qs.results = append(qs.results, data)
	}

	return qs, err
}

func (g *cayleyGraph) Close() error {
	return g.store.Close()
}

func (g *cayleyGraph) addNodeProperties(node *Node) error {
	for key, value := range node.Properties {
		err := g.addProperty(node, key, value)
		if err != nil {
			return err
		}
	}

	return nil
}

func (g *cayleyGraph) addProperty(node *Node, key, value string) error {
	return g.store.AddQuad(quad.Make(node.ID, key, value, node.Label))
}

func (g *cayleyGraph) querySession() *gizmo.Session {
	if g.gizmoQuerySession == nil {
		g.gizmoQuerySession = gizmo.NewSession(g.store)
	}

	return g.gizmoQuerySession
}
