package model

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParsePURL(t *testing.T) {
	cases := []struct {
		name    string
		purl    string
		want    PackageID
		wantErr bool
	}{
		{"npm scoped", "pkg:npm/%40babel/core@7.24.0", PackageID{EcosystemNpm, "@babel", "core", "7.24.0", ""}, false},
		{"pypi", "pkg:pypi/requests@2.31.0", PackageID{EcosystemPyPI, "", "requests", "2.31.0", ""}, false},
		{"maven", "pkg:maven/org.apache/commons@1.0", PackageID{EcosystemMaven, "org.apache", "commons", "1.0", ""}, false},
		{"golang", "pkg:golang/github.com/pkg/errors@v0.9.1", PackageID{EcosystemGo, "github.com/pkg", "errors", "v0.9.1", ""}, false},
		{"github actions", "pkg:githubactions/actions/checkout@v4", PackageID{EcosystemGitHubActions, "actions", "checkout", "v4", ""}, false},
		{"github action subpath", "pkg:github/github/codeql-action@v3#init", PackageID{EcosystemGitHubActions, "github", "codeql-action", "v3", "init"}, false},
		{"unknown type", "pkg:unknown/x@1", PackageID{}, true},
		{"not a purl", "left-pad", PackageID{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePURL(tc.purl)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestPURLRoundTrip(t *testing.T) {
	ids := []PackageID{
		{EcosystemNpm, "@scope", "pkg", "1.0.0", ""},
		{EcosystemPyPI, "", "flask", "3.0.0", ""},
		{EcosystemMaven, "com.google", "guava", "33.0", ""},
		{EcosystemCargo, "", "serde", "1.0.0", ""},
	}
	for _, id := range ids {
		t.Run(id.String(), func(t *testing.T) {
			got, err := ParsePURL(id.PURL())
			require.NoError(t, err)
			assert.Equal(t, id, got)
		})
	}
}

func TestQualifiedName(t *testing.T) {
	cases := []struct {
		id   PackageID
		want string
	}{
		{PackageID{Ecosystem: EcosystemNpm, Namespace: "@a", Name: "b"}, "@a/b"},
		{PackageID{Ecosystem: EcosystemMaven, Namespace: "g", Name: "a"}, "g:a"},
		{PackageID{Ecosystem: EcosystemPyPI, Name: "x"}, "x"},
		{PackageID{Ecosystem: EcosystemGitHubActions, Namespace: "github", Name: "codeql-action", Subpath: "init"}, "github/codeql-action/init"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.id.QualifiedName())
	}
}

func TestEcosystemTable(t *testing.T) {
	for _, e := range Ecosystems() {
		info, err := e.Info()
		require.NoError(t, err)
		got, err := EcosystemFromPURLType(info.PURLType)
		require.NoError(t, err)
		assert.Equal(t, e, got)
		if info.OSVName != "" {
			got, err := EcosystemFromOSV(info.OSVName)
			require.NoError(t, err)
			assert.Equal(t, e, got)
		}
	}
	_, err := Ecosystem("nope").Info()
	assert.Error(t, err)
}

func TestChange(t *testing.T) {
	cases := []struct {
		c          Change
		valid      bool
		introduces bool
	}{
		{ChangeNone, true, false},
		{ChangeAdded, true, true},
		{ChangeUpgraded, true, true},
		{ChangeDowngraded, true, true},
		{ChangeModified, true, true},
		{ChangeRemoved, true, false},
		{ChangeUnchanged, true, false},
		{Change("OTHER"), false, false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.valid, tc.c.Valid(), tc.c)
		assert.Equal(t, tc.introduces, tc.c.Introduces(), tc.c)
	}
}

func TestGraph(t *testing.T) {
	a := PackageID{EcosystemNpm, "", "a", "1", ""}
	b := PackageID{EcosystemNpm, "", "b", "1", ""}
	c := PackageID{EcosystemNpm, "", "c", "1", ""}
	d := PackageID{EcosystemNpm, "", "d", "1", ""}

	g := NewGraph()
	g.AddRoot(a)
	g.AddEdge(a, b)
	g.AddEdge(b, c)
	g.AddEdge(a, c)

	assert.Equal(t, []PackageID{a}, g.Roots())
	assert.Equal(t, []PackageID{b, c}, g.Children(a))
	assert.Equal(t, []PackageID{a, b}, g.Parents(c))
	assert.Equal(t, []PackageID{a, c}, g.PathTo(c))
	assert.Nil(t, g.PathTo(d))

	var edges [][2]PackageID
	g.Edges(func(p, ch PackageID) { edges = append(edges, [2]PackageID{p, ch}) })
	assert.Equal(t, [][2]PackageID{{a, b}, {a, c}, {b, c}}, edges)
}
