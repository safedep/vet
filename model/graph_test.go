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

func TestMayReach(t *testing.T) {
	g := NewGraph()
	a := MustPackageVersion(EcosystemGo, "example.com/a", "1.0.0")
	b := MustPackageVersion(EcosystemGo, "example.com/b", "1.0.0")
	c := MustPackageVersion(EcosystemGo, "example.com/c", "1.0.0")
	o := MustPackageVersion(EcosystemGo, "example.com/open", "1.0.0")
	lone := MustPackageVersion(EcosystemGo, "example.com/lone", "1.0.0")
	g.AddEdge(a, b)
	g.AddEdge(c, o)
	g.MarkOpen(o)

	cases := []struct {
		name string
		from []PackageVersion
		to   PackageVersion
		want bool
	}{
		{"a path of known edges", []PackageVersion{a}, b, true},
		{"no path", []PackageVersion{b}, a, false},
		{"a path that meets an open package", []PackageVersion{c}, lone, true},
		{"an open package itself", []PackageVersion{o}, a, true},
		{"a package with no edge", []PackageVersion{lone}, a, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, g.MayReach(tc.from, tc.to))
		})
	}
	assert.Nil(t, g.PathFrom([]PackageVersion{c}, lone), "PathFrom follows the known edges only")
	assert.Equal(t, []PackageVersion{o}, g.Open())
}
