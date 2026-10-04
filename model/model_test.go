package model

import (
	"encoding/json"
	"testing"

	"github.com/safedep/dry/api/pb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustPV(t *testing.T, eco Ecosystem, name, version string) PackageVersion {
	t.Helper()
	p, err := NewPackageVersion(eco, name, version)
	require.NoError(t, err)
	return p
}

func TestParsePURL(t *testing.T) {
	cases := []struct {
		name        string
		purl        string
		eco         Ecosystem
		raw, rawVer string
		canonical   string
	}{
		{"npm scoped", "pkg:npm/%40babel/core@7.24.0", EcosystemNpm, "@babel/core", "7.24.0", "@babel/core"},
		{"npm keeps case", "pkg:npm/JSONStream@1.0.3", EcosystemNpm, "JSONStream", "1.0.3", "JSONStream"},
		{"pypi folds", "pkg:pypi/Zope.Interface@1.0.0.0", EcosystemPyPI, "Zope.Interface", "1.0.0.0", "zope-interface"},
		{"maven", "pkg:maven/org.apache/commons@1.0", EcosystemMaven, "org.apache:commons", "1.0", "org.apache:commons"},
		{"go keeps case", "pkg:golang/github.com/Masterminds/goutils@v1.1.0", EcosystemGo, "github.com/Masterminds/goutils", "v1.1.0", "github.com/Masterminds/goutils"},
		{"github actions", "pkg:githubactions/actions/checkout@v4", EcosystemGitHubActions, "actions/checkout", "v4", "actions/checkout"},
		{"github action subpath", "pkg:github/github/codeql-action@v3#init", EcosystemGitHubActions, "github/codeql-action", "v3", "github/codeql-action"},
		{"terraform provider", "pkg:terraform/registry.terraform.io/hashicorp/aws@5.31.0", EcosystemTerraformProvider, "registry.terraform.io/hashicorp/aws", "5.31.0", "registry.terraform.io/hashicorp/aws"},
		{"pub", "pkg:pub/http@1.2.0", EcosystemPub, "http", "1.2.0", "http"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePURL(tc.purl)
			require.NoError(t, err)
			assert.Equal(t, tc.eco, got.Ecosystem())
			assert.Equal(t, tc.raw, got.RawName())
			assert.Equal(t, tc.rawVer, got.RawVersion())
			assert.Equal(t, tc.canonical, got.Name())
		})
	}

	for _, bad := range []string{"pkg:deb/debian/curl@1", "pkg:gitlab/a/b@1"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			_, err := ParsePURL(bad)
			assert.ErrorIs(t, err, ErrUnknownEcosystem)
		})
	}

	t.Run("names the unknown type", func(t *testing.T) {
		_, err := ParsePURL("pkg:/Conan/zlib@1.3")
		assert.EqualError(t, err, `unknown ecosystem: PURL type "conan"`)
	})

	t.Run("rejects a string that is not a PURL", func(t *testing.T) {
		_, err := ParsePURL("left-pad")
		assert.ErrorContains(t, err, `parse PURL "left-pad"`)
		assert.NotErrorIs(t, err, ErrUnknownEcosystem)
	})
}

func TestPURLTypesMatchDry(t *testing.T) {
	for typ := range purlTypes {
		t.Run(typ, func(t *testing.T) {
			name := "x"
			if typ == "maven" {
				name = "g/x"
			}
			pv, err := pb.NewPackageVersionFromPurl("pkg:" + typ + "/" + name + "@1")
			require.NoError(t, err)
			_, err = ecosystemOf(pv.Ecosystem())
			assert.NoError(t, err)
		})
	}
}

func TestPURLRoundTrip(t *testing.T) {
	ids := []PackageVersion{
		mustPV(t, EcosystemNpm, "@scope/pkg", "1.0.0"),
		mustPV(t, EcosystemPyPI, "Flask_RESTful", "3.0.0.0"),
		mustPV(t, EcosystemMaven, "com.google:guava", "33.0"),
		mustPV(t, EcosystemCargo, "serde", "1.0.0"),
		mustPV(t, EcosystemGo, "github.com/BurntSushi/toml", "v1.3.2"),
		mustPV(t, EcosystemGitHubActions, "actions/checkout", "v4"),
		mustPV(t, EcosystemTerraformProvider, "registry.terraform.io/hashicorp/aws", "5.31.0"),
		mustPV(t, EcosystemVSCode, "ms-python.python", "2024.1.0"),
	}
	for _, id := range ids {
		t.Run(id.String(), func(t *testing.T) {
			got, err := ParsePURL(id.PURL())
			require.NoError(t, err)
			assert.True(t, id.Equal(got), "%s round-trips through %s", id, id.PURL())
			assert.Equal(t, id.Key(), got.Key())
		})
	}
}

func TestPURLFollowsPurlSpec(t *testing.T) {
	cases := []struct {
		name      string
		id        PackageVersion
		purl      string
		canonical string
	}{
		{"pypi keeps a trailing zero", mustPV(t, EcosystemPyPI, "anthropic-sdk", "0.1.0"), "pkg:pypi/anthropic-sdk@0.1.0", "pkg:pypi/anthropic-sdk@0.1"},
		{"pypi keeps a dot in the name", mustPV(t, EcosystemPyPI, "python.dateutil", "2.8.2"), "pkg:pypi/python.dateutil@2.8.2", "pkg:pypi/python-dateutil@2.8.2"},
		{"pypi lowers case and maps underscore", mustPV(t, EcosystemPyPI, "Flask_RESTful", "3.0.0.0"), "pkg:pypi/flask-restful@3.0.0.0", "pkg:pypi/flask-restful@3"},
		{"pypi with no version", mustPV(t, EcosystemPyPI, "Django", ""), "pkg:pypi/django", "pkg:pypi/django"},
		{"pypi trims the version", mustPV(t, EcosystemPyPI, "django", " 4.2.0 "), "pkg:pypi/django@4.2.0", "pkg:pypi/django@4.2"},
		{"npm is unchanged", mustPV(t, EcosystemNpm, "@babel/core", "7.24.0"), "pkg:npm/%40babel/core@7.24.0", "pkg:npm/%40babel/core@7.24.0"},
		{"maven is unchanged", mustPV(t, EcosystemMaven, "com.google:guava", "33.0"), "pkg:maven/com.google/guava@33.0", "pkg:maven/com.google/guava@33.0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.purl, tc.id.PURL())
			assert.Equal(t, tc.canonical, tc.id.CanonicalPURL())
			got, err := ParsePURL(tc.id.PURL())
			require.NoError(t, err)
			assert.True(t, tc.id.Equal(got))
		})
	}
}

// A new name fold in dry changes the PURL name of its ecosystem. The
// purl-spec name rule of that ecosystem must then join purlSpecName.
func TestPURLSpecNameCoversEachNameFold(t *testing.T) {
	for eco := range ecosystems {
		t.Run(string(eco), func(t *testing.T) {
			id := mustPV(t, eco, "Ab_c.d", "1.0.0")
			if id.Name() == id.RawName() {
				return
			}
			assert.Contains(t, purlSpecName, ecosystems[eco], "the PURL of %s has no purl-spec name rule", eco)
		})
	}
}

func TestPackageVersionIdentity(t *testing.T) {
	t.Run("two spellings of one PyPI release are one key", func(t *testing.T) {
		a := mustPV(t, EcosystemPyPI, "python.dateutil", "2.8")
		b := mustPV(t, EcosystemPyPI, "Python_DateUtil", "2.8.0")
		assert.True(t, a.Equal(b))
		assert.Equal(t, a.Key(), b.Key())
		assert.Equal(t, "python.dateutil", a.RawName())
		assert.Equal(t, "python-dateutil", a.Name())
	})

	t.Run("two Go modules that differ in case are two keys", func(t *testing.T) {
		a := mustPV(t, EcosystemGo, "github.com/Masterminds/goutils", "v1.1.0")
		b := mustPV(t, EcosystemGo, "github.com/masterminds/goutils", "v1.1.0")
		assert.False(t, a.Equal(b))
		assert.NotEqual(t, a.Key(), b.Key())
		assert.False(t, a.SamePackage(b))
	})

	t.Run("name key groups the versions", func(t *testing.T) {
		a := mustPV(t, EcosystemPyPI, "requests", "2.31")
		b := mustPV(t, EcosystemPyPI, "Requests", "2.32.0")
		assert.True(t, a.SamePackage(b))
		assert.NotEqual(t, a.Key(), b.Key())
	})

	t.Run("with version keeps the raw name", func(t *testing.T) {
		a := mustPV(t, EcosystemPyPI, "Requests", "2.31")
		b := a.WithVersion("2.30")
		assert.Equal(t, "Requests", b.RawName())
		assert.Equal(t, "2.30", b.RawVersion())
		assert.True(t, a.SamePackage(b))
	})

	t.Run("string shows the raw form", func(t *testing.T) {
		assert.Equal(t, "pypi/Zope.Interface@1.0.0.0", mustPV(t, EcosystemPyPI, "Zope.Interface", "1.0.0.0").String())
		assert.Equal(t, "npm/x", mustPV(t, EcosystemNpm, "x", "").String())
	})

	t.Run("raw form on the wire", func(t *testing.T) {
		wire := mustPV(t, EcosystemPyPI, "X", "1.0.0.0.0.0").RawProto()
		assert.Equal(t, "X", wire.GetPackage().GetName())
		assert.Equal(t, "1.0.0.0.0.0", wire.GetVersion())
	})

	t.Run("compare uses the ecosystem order", func(t *testing.T) {
		got, err := mustPV(t, EcosystemPyPI, "x", "1.0rc1").Compare(mustPV(t, EcosystemPyPI, "x", "1.0"))
		require.NoError(t, err)
		assert.Equal(t, -1, got)
	})

	t.Run("bad input", func(t *testing.T) {
		_, err := NewPackageVersion("nope", "x", "1")
		assert.Error(t, err)
		_, err = NewPackageVersion(EcosystemNpm, "", "1")
		assert.Error(t, err)
		assert.True(t, PackageVersion{}.IsZero())
	})
}

func TestPackageVersionJSON(t *testing.T) {
	in := mustPV(t, EcosystemPyPI, "Zope.Interface", "1.0.0.0")
	b, err := json.Marshal(in)
	require.NoError(t, err)
	assert.JSONEq(t, `{"ecosystem":"pypi","name":"zope-interface","version":"1","raw_name":"Zope.Interface","raw_version":"1.0.0.0","purl":"pkg:pypi/zope.interface@1.0.0.0"}`, string(b))

	var out PackageVersion
	require.NoError(t, json.Unmarshal(b, &out))
	assert.True(t, in.Equal(out))
	assert.Equal(t, "Zope.Interface", out.RawName())

	assert.Error(t, json.Unmarshal([]byte(`{"ecosystem":"nope","raw_name":"x"}`), &out))
}

// TestEcosystemsMatchDry checks that each vet ecosystem name is the dry name
// of its SafeDep API value, so every SafeDep tool prints the same name.
func TestEcosystemsMatchDry(t *testing.T) {
	for e, value := range ecosystems {
		name, err := pb.EcosystemName(value)
		require.NoError(t, err)
		assert.Equal(t, string(e), name)
		assert.True(t, e.Valid())
	}
	assert.False(t, Ecosystem("nope").Valid())
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
	a := mustPV(t, EcosystemNpm, "a", "1")
	b := mustPV(t, EcosystemNpm, "b", "1")
	c := mustPV(t, EcosystemNpm, "c", "1")
	d := mustPV(t, EcosystemNpm, "d", "1")

	g := NewGraph()
	g.AddRoot(a)
	g.AddEdge(a, b)
	g.AddEdge(b, c)
	g.AddEdge(a, c)

	keys := func(ids []PackageVersion) []PackageKey {
		var out []PackageKey
		for _, id := range ids {
			out = append(out, id.Key())
		}
		return out
	}
	assert.Equal(t, keys([]PackageVersion{a}), keys(g.Roots()))
	assert.Equal(t, keys([]PackageVersion{b, c}), keys(g.Children(a)))
	assert.Equal(t, keys([]PackageVersion{a, b}), keys(g.Parents(c)))
	assert.Equal(t, keys([]PackageVersion{a, c}), keys(g.PathTo(c)))
	assert.Nil(t, g.PathTo(d))

	var edges [][2]PackageKey
	g.Edges(func(p, ch PackageVersion) { edges = append(edges, [2]PackageKey{p.Key(), ch.Key()}) })
	assert.Equal(t, [][2]PackageKey{{a.Key(), b.Key()}, {a.Key(), c.Key()}, {b.Key(), c.Key()}}, edges)
}

func TestGraphMergesSpellings(t *testing.T) {
	root := mustPV(t, EcosystemPyPI, "app", "1")
	g := NewGraph()
	g.AddRoot(root)
	g.AddEdge(root, mustPV(t, EcosystemPyPI, "Zope.Interface", "5.0"))
	g.AddEdge(root, mustPV(t, EcosystemPyPI, "zope_interface", "5.0.0"))

	children := g.Children(root)
	require.Len(t, children, 1)
	assert.Equal(t, "Zope.Interface", children[0].RawName(), "the graph keeps the first spelling")
	assert.Len(t, g.PathTo(mustPV(t, EcosystemPyPI, "zope-interface", "5")), 2)
}

func TestNameIs(t *testing.T) {
	cases := []struct {
		eco  Ecosystem
		pkg  string
		name string
		want bool
	}{
		{EcosystemPyPI, "python.dateutil", "python-dateutil", true},
		{EcosystemPyPI, "Zope.Interface", "zope_interface", true},
		{EcosystemPyPI, "requests", "request", false},
		{EcosystemNpm, "JSONStream", "jsonstream", false},
		{EcosystemGo, "github.com/Masterminds/goutils", "github.com/masterminds/goutils", false},
	}
	for _, tc := range cases {
		t.Run(tc.pkg+"="+tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, mustPV(t, tc.eco, tc.pkg, "1.0").NameIs(tc.name))
		})
	}
}

func TestMatchName(t *testing.T) {
	cases := []struct {
		eco     Ecosystem
		pkg     string
		pattern string
		want    bool
	}{
		{EcosystemPyPI, "Acme.Utils", "acme-*", true},
		{EcosystemPyPI, "acme_utils", "Acme.*", true},
		{EcosystemPyPI, "other", "acme-*", false},
		{EcosystemPyPI, "acme-x", "acme-[xy]", true},
		{EcosystemNpm, "@acme/utils", "@acme/*", true},
		{EcosystemNpm, "@Acme/utils", "@acme/*", false},
	}
	for _, tc := range cases {
		t.Run(tc.pkg+"~"+tc.pattern, func(t *testing.T) {
			got, err := mustPV(t, tc.eco, tc.pkg, "1.0").MatchName(tc.pattern)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}

	_, err := mustPV(t, EcosystemPyPI, "a", "1").MatchName("a[")
	assert.Error(t, err)
}
