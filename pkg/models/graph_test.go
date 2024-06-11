package models

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

type dgTestNode struct {
	Name string `json:"Name"`
}

func (n *dgTestNode) Id() string {
	return n.Name
}

func dependencyGraphAddTestData(dg *DependencyGraph[*dgTestNode]) {
	dg.AddDependency(&dgTestNode{Name: "a"}, &dgTestNode{Name: "b"})
	dg.AddDependency(&dgTestNode{Name: "a"}, &dgTestNode{Name: "c"})
	dg.AddDependency(&dgTestNode{Name: "b"}, &dgTestNode{Name: "c"})
	dg.AddDependency(&dgTestNode{Name: "c"}, &dgTestNode{Name: "d"})
}

func TestDependencyGraphIsPresent(t *testing.T) {
	dg := NewDependencyGraph[*dgTestNode]()
	assert.NotNil(t, dg)

	assert.False(t, dg.Present())

	dg.SetPresent(true)
	assert.True(t, dg.Present())
}

func TestDependencyGraphGetDependencies(t *testing.T) {
	dg := NewDependencyGraph[*dgTestNode]()
	assert.NotNil(t, dg)

	dependencyGraphAddTestData(dg)

	assert.Equal(t, []*dgTestNode{{Name: "b"}, {Name: "c"}}, dg.GetDependencies(&dgTestNode{Name: "a"}))
	assert.Equal(t, []*dgTestNode{{Name: "c"}}, dg.GetDependencies(&dgTestNode{Name: "b"}))
	assert.Equal(t, []*dgTestNode{{Name: "d"}}, dg.GetDependencies(&dgTestNode{Name: "c"}))
	assert.Equal(t, []*dgTestNode{}, dg.GetDependencies(&dgTestNode{Name: "d"}))
}

func TestDependencyGraphGetDependents(t *testing.T) {
	dg := NewDependencyGraph[*dgTestNode]()
	assert.NotNil(t, dg)

	dependencyGraphAddTestData(dg)

	assert.Equal(t, []*dgTestNode{}, dg.GetDependents(&dgTestNode{Name: "a"}))
	assert.Equal(t, []*dgTestNode{{Name: "a"}}, dg.GetDependents(&dgTestNode{Name: "b"}))
	assert.Equal(t, []*dgTestNode{{Name: "c"}}, dg.GetDependents(&dgTestNode{Name: "d"}))

	dependents := dg.GetDependents(&dgTestNode{Name: "c"})

	assert.Equal(t, 2, len(dependents))
	assert.Contains(t, dependents, &dgTestNode{Name: "b"})
	assert.Contains(t, dependents, &dgTestNode{Name: "a"})
}

func TestDependencyGraphGetNodes(t *testing.T) {
	dg := NewDependencyGraph[*dgTestNode]()
	assert.NotNil(t, dg)

	dependencyGraphAddTestData(dg)

	nodes := dg.GetNodes()
	assert.Equal(t, 4, len(nodes))

	nodeNames := []string{}
	for _, node := range nodes {
		nodeNames = append(nodeNames, node.Data.Name)
	}

	assert.ElementsMatch(t, []string{"a", "b", "c", "d"}, nodeNames)
}

func TestDependencyGraphPathToRoot(t *testing.T) {
	dg := NewDependencyGraph[*dgTestNode]()
	assert.NotNil(t, dg)

	dependencyGraphAddTestData(dg)

	assert.Equal(t,
		[]*dgTestNode{
			{Name: "d"},
			{Name: "c"},
			{Name: "a"},
		}, dg.PathToRoot(&dgTestNode{Name: "d"}))
}

func TestDependencyGraphMarshalJSON(t *testing.T) {
	dg := NewDependencyGraph[*dgTestNode]()
	assert.NotNil(t, dg)

	dependencyGraphAddTestData(dg)
	dg.SetPresent(true)

	_, err := json.Marshal(dg)
	assert.Nil(t, err)
}

func TestDependencyGraphUnmarshalJSON(t *testing.T) {
	dg := NewDependencyGraph[*dgTestNode]()
	assert.NotNil(t, dg)

	dependencyGraphAddTestData(dg)
	dg.SetPresent(true)

	data, err := json.Marshal(dg)
	assert.Nil(t, err)

	dg2 := NewDependencyGraph[*dgTestNode]()
	assert.NotNil(t, dg2)

	err = json.Unmarshal(data, dg2)
	assert.Nil(t, err)
	assert.Equal(t, dg, dg2)
}
