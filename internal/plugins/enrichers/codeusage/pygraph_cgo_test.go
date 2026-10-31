//go:build cgo

package codeusage

import (
	"context"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/safedep/code/distgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
)

func pyPackage(name, version string) *model.Package {
	return &model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, name, version)}
}

func pyText(s string) *fstest.MapFile { return &fstest.MapFile{Data: []byte(s)} }

// pySite builds a site-packages directory: each distribution is a name, a
// version and the files that its RECORD lists, with their content.
func pySite(dists ...pyDist) fstest.MapFS {
	out := fstest.MapFS{}
	for _, d := range dists {
		dir := strings.ReplaceAll(d.name, "-", "_") + "-" + d.version + ".dist-info"
		out[dir+"/METADATA"] = pyText("Name: " + d.name + "\nVersion: " + d.version + "\n")
		record := ""
		for f, content := range d.files {
			record += f + ",,\n"
			out[f] = pyText(content)
		}
		out[dir+"/RECORD"] = pyText(record)
	}
	return out
}

type pyDist struct {
	name, version string
	files         map[string]string
}

func TestDistributionGraph(t *testing.T) {
	type edge struct{ from, to string }
	cases := []struct {
		name      string
		project   fstest.MapFS
		site      fstest.MapFS
		pkgs      []*model.Package
		roots     []string
		testRoots []string
		edges     []edge
		open      []string
		why       string
	}{
		{
			name:    "the imports of the reached distributions",
			project: fstest.MapFS{"main.py": pyText("import requests\n")},
			site: pySite(
				pyDist{"requests", "2.31.0", map[string]string{"requests/__init__.py": "import urllib3\nimport idna\n"}},
				pyDist{"urllib3", "2.0.7", map[string]string{"urllib3/__init__.py": "import socket\n"}},
				pyDist{"idna", "3.6", map[string]string{"idna/__init__.py": ""}},
				pyDist{"six", "1.16.0", map[string]string{"six.py": "import requests\n"}},
			),
			pkgs:  []*model.Package{pyPackage("requests", "2.31.0"), pyPackage("urllib3", "2.0.7"), pyPackage("idna", "3.6"), pyPackage("six", "1.16.0")},
			roots: []string{"requests"},
			edges: []edge{{"requests", "urllib3"}, {"requests", "idna"}},
			open:  []string{"six"},
		},
		{
			name:    "a distribution that the manifest does not list passes its edges on",
			project: fstest.MapFS{"main.py": pyText("import wrap\n")},
			site: pySite(
				pyDist{"wrap", "1.0.0", map[string]string{"wrap/__init__.py": "import requests\n"}},
				pyDist{"requests", "2.31.0", map[string]string{"requests/__init__.py": ""}},
			),
			pkgs:  []*model.Package{pyPackage("requests", "2.31.0")},
			roots: []string{"requests"},
		},
		{
			name:    "a root that only a test file imports is a test root",
			project: fstest.MapFS{"main.py": pyText("import requests\n"), "tests/test_app.py": pyText("import six\nimport requests\n")},
			site: pySite(
				pyDist{"requests", "2.31.0", map[string]string{"requests/__init__.py": ""}},
				pyDist{"six", "1.16.0", map[string]string{"six.py": ""}},
			),
			pkgs:      []*model.Package{pyPackage("requests", "2.31.0"), pyPackage("six", "1.16.0")},
			roots:     []string{"requests", "six"},
			testRoots: []string{"six"},
		},
		{
			name:    "a package that is not installed is open",
			project: fstest.MapFS{"main.py": pyText("import requests\n")},
			site:    pySite(pyDist{"requests", "2.31.0", map[string]string{"requests/__init__.py": ""}}),
			pkgs:    []*model.Package{pyPackage("requests", "2.31.0"), pyPackage("django", "4.2.0")},
			roots:   []string{"requests"},
			open:    []string{"django"},
		},
		{
			name:    "an open distribution that the project imports",
			project: fstest.MapFS{"main.py": pyText("import lxml\n")},
			site: pySite(
				pyDist{"lxml", "4.9.0", map[string]string{"lxml/__init__.py": "", "lxml/etree.cpython-312-x86_64-linux-gnu.so": ""}},
				pyDist{"six", "1.16.0", map[string]string{"six.py": ""}},
			),
			pkgs:  []*model.Package{pyPackage("lxml", "4.9.0"), pyPackage("six", "1.16.0")},
			roots: []string{"lxml"},
			open:  []string{"lxml"},
		},
		{
			name:    "a manifest package that imports an open distribution that the manifest does not list is open",
			project: fstest.MapFS{"main.py": pyText("import requests\n")},
			site: pySite(
				pyDist{"requests", "2.31.0", map[string]string{"requests/__init__.py": "import wrap\n"}},
				pyDist{"wrap", "1.0.0", map[string]string{"wrap/__init__.py": "import importlib\nimportlib.import_module(name)\n"}},
			),
			pkgs:  []*model.Package{pyPackage("requests", "2.31.0")},
			roots: []string{"requests"},
			open:  []string{"requests"},
		},
		{
			name:    "a name at two versions takes the installed one, and the other is open",
			project: fstest.MapFS{"main.py": pyText("import requests\n")},
			site:    pySite(pyDist{"requests", "2.31.0", map[string]string{"requests/__init__.py": ""}}),
			pkgs:    []*model.Package{pyPackage("requests", "2.30.0"), pyPackage("requests", "2.31.0")},
			roots:   []string{"requests"},
			open:    []string{"requests"},
		},
		{
			name:    "a name at two versions in the other order",
			project: fstest.MapFS{"main.py": pyText("import requests\n")},
			site:    pySite(pyDist{"requests", "2.31.0", map[string]string{"requests/__init__.py": ""}}),
			pkgs:    []*model.Package{pyPackage("requests", "2.31.0"), pyPackage("requests", "2.30.0")},
			roots:   []string{"requests"},
			open:    []string{"requests"},
		},
		{
			name:    "another version of an unreached package is open",
			project: fstest.MapFS{"main.py": pyText("import six\n")},
			site: pySite(
				pyDist{"requests", "2.30.0", map[string]string{"requests/__init__.py": ""}},
				pyDist{"six", "1.16.0", map[string]string{"six.py": ""}},
			),
			pkgs:  []*model.Package{pyPackage("requests", "2.31.0"), pyPackage("six", "1.16.0")},
			roots: []string{"six"},
			open:  []string{"requests"},
		},
		{
			name:    "a version that vet cannot read is another version",
			project: fstest.MapFS{"main.py": pyText("import requests\n")},
			site:    pySite(pyDist{"requests", "not a version", map[string]string{"requests/__init__.py": ""}}),
			pkgs:    []*model.Package{pyPackage("requests", "2.31.0")},
			why:     "the environment holds requests not a version, and the manifest 2.31.0",
		},
		{
			name:    "another version of a reached package",
			project: fstest.MapFS{"main.py": pyText("import requests\n")},
			site:    pySite(pyDist{"requests", "2.30.0", map[string]string{"requests/__init__.py": ""}}),
			pkgs:    []*model.Package{pyPackage("requests", "2.31.0")},
			why:     "the environment holds requests 2.30.0, and the manifest 2.31.0",
		},
		{
			name:    "a manifest with no version takes the installed version",
			project: fstest.MapFS{"main.py": pyText("import requests\n")},
			site:    pySite(pyDist{"requests", "2.30.0", map[string]string{"requests/__init__.py": ""}}),
			pkgs:    []*model.Package{pyPackage("requests", "")},
			roots:   []string{"requests"},
		},
		{
			name:    "the project imports what no distribution holds",
			project: fstest.MapFS{"main.py": pyText("import missing\n")},
			site:    pySite(pyDist{"requests", "2.31.0", map[string]string{"requests/__init__.py": ""}}),
			pkgs:    []*model.Package{pyPackage("requests", "2.31.0")},
			why:     "the project can import any distribution: main.py:1 imports missing, which no distribution holds",
		},
		{
			name:    "the project imports an open distribution that is no package of the manifest",
			project: fstest.MapFS{"main.py": pyText("import wrap\n")},
			site: pySite(
				pyDist{"wrap", "1.0.0", map[string]string{"wrap/__init__.py": "import importlib\nimportlib.import_module(name)\n"}},
				pyDist{"requests", "2.31.0", map[string]string{"requests/__init__.py": ""}},
			),
			pkgs: []*model.Package{pyPackage("requests", "2.31.0")},
			why:  "the project imports wrap, which vet cannot read",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g, err := distgraph.Build(context.Background(), distgraph.Input{ProjectFS: c.project, SitePackages: []fs.FS{c.site}})
			require.NoError(t, err)
			out, why := distributionGraph(g, c.pkgs)
			assert.Equal(t, c.why, why)
			if c.why != "" {
				assert.Nil(t, out)
				return
			}
			require.NotNil(t, out)
			assert.True(t, out.Imports())
			assert.ElementsMatch(t, c.roots, names(out.Roots()))
			assert.ElementsMatch(t, c.testRoots, names(out.TestRoots()))
			assert.ElementsMatch(t, c.open, names(out.Open()))
			var edges []edge
			out.Edges(func(parent, child model.PackageVersion) { edges = append(edges, edge{parent.Name(), child.Name()}) })
			assert.ElementsMatch(t, c.edges, edges)
			for _, id := range out.Roots() {
				assert.True(t, slices.ContainsFunc(c.pkgs, func(p *model.Package) bool { return p.ID.Equal(id) }), "the root %s is a package of the manifest at its version", id)
			}
		})
	}
}

func TestDistributionGraphVersionsOfOneName(t *testing.T) {
	site := pySite(pyDist{"requests", "2.31.0", map[string]string{"requests/__init__.py": ""}})
	g, err := distgraph.Build(context.Background(), distgraph.Input{ProjectFS: fstest.MapFS{"main.py": pyText("import requests\n")}, SitePackages: []fs.FS{site}})
	require.NoError(t, err)
	old, installed := pyPackage("requests", "2.30.0"), pyPackage("requests", "2.31.0")
	for _, pkgs := range [][]*model.Package{{old, installed}, {installed, old}} {
		out, why := distributionGraph(g, pkgs)
		require.Empty(t, why)
		assert.Equal(t, []model.PackageVersion{installed.ID}, out.Roots(), "the installed version is the root")
		assert.True(t, out.IsOpen(old.ID), "the version that is not installed is open")
		assert.False(t, out.IsOpen(installed.ID))
	}
}

func names(ids []model.PackageVersion) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = id.Name()
	}
	slices.Sort(out)
	return out
}

func TestGraphOfAPythonManifest(t *testing.T) {
	t.Setenv("VIRTUAL_ENV", "")
	t.Run("a target with a virtual environment", func(t *testing.T) {
		dir := t.TempDir()
		pythonVenv(t, dir, t.TempDir(), ".venv")
		writeTree(t, dir, map[string]string{"requirements.txt": "requests==2.31.0\nsix==1.16.0\n", "main.py": "import requests\n"})
		e := NewWith(dir, Options{}, nil)
		m := &model.Manifest{Path: "requirements.txt", Ecosystem: model.EcosystemPyPI, Packages: []*model.Package{pyPackage("requests", "2.31.0"), pyPackage("six", "1.16.0")}}
		g, err := e.Graph(context.Background(), m)
		require.NoError(t, err)
		require.NotNil(t, g)
		assert.Equal(t, []string{"requests"}, names(g.Roots()))
		assert.Equal(t, []string{"six"}, names(g.Open()), "an unreached distribution is not walked, so its imports are unknown, and the .venv of the target is no code of the project")
		assert.Empty(t, e.graphDiagnostics())
	})
	t.Run("a target with no virtual environment", func(t *testing.T) {
		dir := t.TempDir()
		writeTree(t, dir, map[string]string{"requirements.txt": "requests==2.31.0\n", "main.py": "import requests\n"})
		e := NewWith(dir, Options{}, nil)
		g, err := e.Graph(context.Background(), &model.Manifest{Path: "requirements.txt", Ecosystem: model.EcosystemPyPI, Packages: []*model.Package{pyPackage("requests", "2.31.0")}})
		require.NoError(t, err)
		assert.Nil(t, g)
		diags := e.graphDiagnostics()
		require.Len(t, diags, 1)
		assert.Equal(t, CodeModuleGraph, diags[0].Code)
		assert.Equal(t, "vet builds no import graph for requirements.txt, because "+dir+" has no virtual environment. Install the project in a virtual environment, as pip install -r requirements.txt or uv sync, then scan again.", diags[0].Message)
	})
	t.Run("a manifest with a virtual environment of its own", func(t *testing.T) {
		dir := t.TempDir()
		writeTree(t, dir, map[string]string{
			"services/api/requirements.txt": "requests==2.31.0\n", "services/api/main.py": "import requests\n",
			"services/web/main.py": "import missing\n",
		})
		pythonVenv(t, filepath.Join(dir, "services", "api"), t.TempDir(), ".venv")
		e := NewWith(dir, Options{}, nil)
		g, err := e.Graph(context.Background(), &model.Manifest{Path: "services/api/requirements.txt", Ecosystem: model.EcosystemPyPI, Packages: []*model.Package{pyPackage("requests", "2.31.0")}})
		require.NoError(t, err)
		require.NotNil(t, g, "the project of the manifest is its directory, so the import of the other service does not open it")
		assert.Equal(t, []string{"requests"}, names(g.Roots()))
		assert.Empty(t, e.graphDiagnostics())
	})
	t.Run("the graph of an environment is built once", func(t *testing.T) {
		dir := t.TempDir()
		pythonVenv(t, dir, t.TempDir(), ".venv")
		writeTree(t, dir, map[string]string{"requirements.txt": "requests==2.31.0\n", "pyproject.toml": "", "main.py": "import requests\n"})
		e := NewWith(dir, Options{}, nil)
		for _, m := range []string{"requirements.txt", "pyproject.toml"} {
			g, err := e.Graph(context.Background(), &model.Manifest{Path: m, Ecosystem: model.EcosystemPyPI, Packages: []*model.Package{pyPackage("requests", "2.31.0")}})
			require.NoError(t, err)
			require.NotNil(t, g)
		}
		assert.Len(t, e.pyGraphs, 1)
	})
	t.Run("an open distribution that the project reaches", func(t *testing.T) {
		dir := t.TempDir()
		site := pythonVenv(t, dir, t.TempDir(), ".venv")
		mkfile(t, filepath.Join(site, "requests", "api.py"), "import urllib3\nimport fast\n")
		writeTree(t, dir, map[string]string{"requirements.txt": "requests==2.31.0\n", "main.py": "import requests\n"})
		e := NewWith(dir, Options{}, nil)
		g, err := e.Graph(context.Background(), &model.Manifest{Path: "requirements.txt", Ecosystem: model.EcosystemPyPI, Packages: []*model.Package{pyPackage("requests", "2.31.0"), pyPackage("fast", "1.0.0")}})
		require.NoError(t, err)
		require.NotNil(t, g)
		assert.Equal(t, []string{"fast"}, names(g.Open()), "a distribution with no Python file can import any distribution")
		diags := e.graphDiagnostics()
		require.Len(t, diags, 1)
		assert.Equal(t, "vet cannot read the imports of 1 Python distribution of requirements.txt, such as fast of requirements.txt, so reach can be unknown for the packages that they can import. An extension module, an import of a computed name or an import of a module that no distribution holds hides the imports of a distribution.", diags[0].Message)
	})
}
