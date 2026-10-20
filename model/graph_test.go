package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathFrom(t *testing.T) {
	g := NewGraph()
	a := MustPackageVersion(EcosystemNpm, "a", "1.0.0")
	b := MustPackageVersion(EcosystemNpm, "b", "1.0.0")
	c := MustPackageVersion(EcosystemNpm, "c", "1.0.0")
	d := MustPackageVersion(EcosystemNpm, "d", "1.0.0")
	x := MustPackageVersion(EcosystemNpm, "x", "1.0.0")
	g.AddRoot(a)
	g.AddEdge(a, b)
	g.AddEdge(b, c)
	g.AddEdge(d, c)
	g.AddEdge(x, a)

	assert.Equal(t, []PackageVersion{b, c}, g.PathFrom([]PackageVersion{a, b}, c), "the shortest path starts at the nearest source")
	assert.Equal(t, []PackageVersion{b, c}, g.PathFrom([]PackageVersion{d, b}, c), "a tie goes to the first source in key order")
	assert.Equal(t, []PackageVersion{a}, g.PathFrom([]PackageVersion{a}, a))
	assert.Nil(t, g.PathFrom([]PackageVersion{c}, a), "an edge goes from parent to child only")
	assert.Nil(t, g.PathFrom(nil, c))
}
