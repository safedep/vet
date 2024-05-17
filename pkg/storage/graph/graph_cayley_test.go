package graph

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCayleyGraphQuery(t *testing.T) {
	graphModelLinks := []Edge{
		{
			Name: "knows",
			From: &Node{
				ID:         "alice",
				Label:      "person",
				Properties: map[string]string{"name": "Alice"},
			},
			To: &Node{
				ID:         "bob",
				Label:      "person",
				Properties: map[string]string{"name": "Bob"},
			},
			Properties: map[string]string{"since": "2010"},
		},
		{
			Name: "knows",
			From: &Node{
				ID:         "alice",
				Label:      "person",
				Properties: map[string]string{"name": "Alice"},
			},
			To: &Node{
				ID:         "charlie",
				Label:      "person",
				Properties: map[string]string{"name": "Charlie"},
			},
			Properties: map[string]string{"since": "2012"},
		},
		{
			Name: "knows",
			From: &Node{
				ID:         "bob",
				Label:      "person",
				Properties: map[string]string{"name": "Bob"},
			},
			To: &Node{
				ID:         "dexter",
				Label:      "person",
				Properties: map[string]string{"name": "Dexter"},
			},
			Properties: map[string]string{"since": "2014"},
		},
	}

	config := &LocalPropertyGraphConfig{
		Name:         "test",
		DatabasePath: "test.db",
	}

	g, err := NewInMemoryPropertyGraph(config)
	assert.Nil(t, err)

	defer g.Close()

	for _, link := range graphModelLinks {
		err = g.Link(&link)
		assert.Nil(t, err)
	}

	// Alice knows Bob and Charlie
	query := `
		g.V("alice").Out("knows").All()
	`

	result, err := g.Query(context.TODO(), query)
	assert.Nil(t, err)

	strings, err := result.Strings()
	assert.Nil(t, err)

	assert.ElementsMatch(t, []string{"bob", "charlie"}, strings)

	// Alice do not know Dexter
	query = `
		g.V("alice").Out("knows").Has("name", "Dexter").All()
	`

	result, err = g.Query(context.TODO(), query)
	assert.Nil(t, err)

	strings, err = result.Strings()
	assert.Nil(t, err)

	assert.Empty(t, strings)
}
