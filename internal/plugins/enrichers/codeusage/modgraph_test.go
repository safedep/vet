package codeusage

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/safedep/code/modgraph"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
)

func goFile(pkg string, imports ...string) *fstest.MapFile {
	var b strings.Builder
	fmt.Fprintf(&b, "package %s\n\n", pkg)
	for _, imp := range imports {
		fmt.Fprintf(&b, "import _ %q\n", imp)
	}
	return &fstest.MapFile{Data: []byte(b.String())}
}

func goSource(path string, fsys fstest.MapFS) modgraph.Source {
	return modgraph.Source{Module: modgraph.Module{Path: path, Version: "v1.0.0"}, FS: fsys}
}

func localSource(path string, fsys fs.FS) modgraph.Source {
	return modgraph.Source{Module: modgraph.Module{Path: path}, Origin: modgraph.Module{Path: "../local"}, FS: fsys}
}

func goPackage(path string) *model.Package {
	return &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, path, "1.0.0")}
}

func TestModuleGraph(t *testing.T) {
	type edge struct{ from, to string }
	cases := []struct {
		name    string
		imports []string
		modules []modgraph.Source
		pkgs    []*model.Package
		roots   []string
		edges   []edge
		open    []string
		why     string
	}{
		{
			name:    "the imports of the reached packages",
			imports: []string{"example.com/a"},
			modules: []modgraph.Source{
				goSource("example.com/a", fstest.MapFS{"a.go": goFile("a", "example.com/b", "fmt")}),
				goSource("example.com/b", fstest.MapFS{"b.go": goFile("b")}),
				goSource("example.com/unused", fstest.MapFS{"u.go": goFile("u", "example.com/b")}),
			},
			pkgs:  []*model.Package{goPackage("example.com/a"), goPackage("example.com/b"), goPackage("example.com/unused")},
			roots: []string{"example.com/a"},
			edges: []edge{{"example.com/a", "example.com/b"}},
			open:  []string{"example.com/unused"},
		},
		{
			name:    "a local replacement passes its edges on",
			imports: []string{"example.com/local"},
			modules: []modgraph.Source{
				localSource("example.com/local", fstest.MapFS{"l.go": goFile("l", "example.com/x")}),
				goSource("example.com/x", fstest.MapFS{"x.go": goFile("x")}),
			},
			pkgs:  []*model.Package{goPackage("example.com/x")},
			roots: []string{"example.com/x"},
		},
		{
			name:    "a replacement is the package of the module that it replaces",
			imports: []string{"example.com/upstream"},
			modules: []modgraph.Source{
				goSource("example.com/upstream", fstest.MapFS{"u.go": goFile("u", "example.com/x")}),
				goSource("example.com/x", fstest.MapFS{"x.go": goFile("x")}),
			},
			pkgs: []*model.Package{
				{ID: model.MustPackageVersion(model.EcosystemGo, "example.com/fork", "1.1.0"), Replaces: "example.com/upstream"},
				goPackage("example.com/x"),
			},
			roots: []string{"example.com/fork"},
			edges: []edge{{"example.com/fork", "example.com/x"}},
		},
		{
			name:    "a module with no source is open",
			imports: []string{"example.com/a", "example.com/gone"},
			modules: []modgraph.Source{
				goSource("example.com/a", fstest.MapFS{"a.go": goFile("a")}),
				{Module: modgraph.Module{Path: "example.com/gone", Version: "v1.0.0"}},
			},
			pkgs:  []*model.Package{goPackage("example.com/a"), goPackage("example.com/gone")},
			roots: []string{"example.com/a", "example.com/gone"},
			open:  []string{"example.com/gone"},
		},
		{
			name:    "a module that imports through an open local module is open",
			imports: []string{"example.com/a"},
			modules: []modgraph.Source{
				goSource("example.com/a", fstest.MapFS{"a.go": goFile("a", "example.com/local")}),
				localSource("example.com/local", nil),
			},
			pkgs:  []*model.Package{goPackage("example.com/a")},
			roots: []string{"example.com/a"},
			open:  []string{"example.com/a"},
		},
		{
			name:    "the main module imports an open local module",
			imports: []string{"example.com/local"},
			modules: []modgraph.Source{localSource("example.com/local", nil)},
			why:     "the main module imports example.com/local, which vet cannot read",
		},
		{
			name:    "a reached module that is no package",
			imports: []string{"example.com/a"},
			modules: []modgraph.Source{
				goSource("example.com/a", fstest.MapFS{"a.go": goFile("a", "example.com/lost")}),
				goSource("example.com/lost", fstest.MapFS{"l.go": goFile("l", "example.com/x")}),
				goSource("example.com/x", fstest.MapFS{"x.go": goFile("x")}),
			},
			pkgs: []*model.Package{goPackage("example.com/a"), goPackage("example.com/x")},
			why:  "the module example.com/lost@v1.0.0 is no package of the manifest",
		},
		{
			name:    "the main module imports a path of no module",
			imports: []string{"example.com/missing"},
			why:     "the main module can import any module",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			main := fstest.MapFS{
				"go.mod":  {Data: []byte("module example.com/app\n\ngo 1.22\n")},
				"main.go": goFile("main", tc.imports...),
			}
			g, err := modgraph.Build(context.Background(), modgraph.Input{MainFS: main, Modules: tc.modules})
			require.NoError(t, err)
			got, why := moduleGraph(g, tc.pkgs, localReplacements(tc.modules))
			if tc.why != "" {
				assert.Nil(t, got)
				assert.Contains(t, why, tc.why)
				return
			}
			require.Empty(t, why)
			require.NotNil(t, got)
			assert.True(t, got.Imports())
			var roots, open []string
			for _, r := range got.Roots() {
				roots = append(roots, r.RawName())
			}
			for _, o := range got.Open() {
				open = append(open, o.RawName())
			}
			var edges []edge
			got.Edges(func(p, c model.PackageVersion) { edges = append(edges, edge{p.RawName(), c.RawName()}) })
			assert.Equal(t, tc.roots, roots)
			assert.Equal(t, tc.edges, edges)
			assert.Equal(t, tc.open, open)
		})
	}
}

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for name, data := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(data), 0o600))
	}
}

func TestGraphOfAGoMod(t *testing.T) {
	const gomod = "module example.com/app\n\ngo 1.22\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n\texample.com/gone v1.0.0\n)\n"
	cases := []struct {
		name   string
		files  map[string]string
		open   []string
		note   string
		none   bool
		gowork string
		// goworkVia spells GOWORK through a link to the module directory, or
		// as a relative path.
		goworkVia string
		// outerWork is a go.work in the parent of the scan root.
		outerWork string
	}{
		{
			name:  "an unreached module has no source",
			files: map[string]string{"go.mod": gomod, "main.go": "package main\n\nimport _ \"example.com/a\"\n"},
			open:  []string{"example.com/gone"},
		},
		{
			name:  "a reached module has no source",
			files: map[string]string{"go.mod": gomod, "main.go": "package main\n\nimport (\n\t_ \"example.com/a\"\n\t_ \"example.com/gone\"\n)\n"},
			open:  []string{"example.com/gone"},
			note:  "vet cannot read the imports of 1 Go module of go.mod, such as example.com/gone",
		},
		{
			name:  "a workspace",
			files: map[string]string{"go.mod": gomod, "main.go": "package main\n", "go.work": "go 1.22\n\nuse .\n"},
			note:  "because the workspace go.work holds it",
			none:  true,
		},
		{
			name:  "a workspace that does not use the module",
			files: map[string]string{"go.mod": gomod, "main.go": "package main\n\nimport _ \"example.com/a\"\n", "go.work": "go 1.22\n\nuse ./other\n"},
			open:  []string{"example.com/gone"},
		},
		{
			name:   "GOWORK names a workspace that uses the module",
			files:  map[string]string{"go.mod": gomod, "main.go": "package main\n", "ws/go.work": "go 1.22\n\nuse ..\n"},
			gowork: "ws/go.work",
			note:   "because the workspace",
			none:   true,
		},
		{
			name:      "a workspace above the scan root",
			files:     map[string]string{"go.mod": gomod, "main.go": "package main\n"},
			outerWork: "go 1.22\n\nuse ./mod\n",
			note:      "/go.work holds it",
			none:      true,
		},
		{
			name:      "GOWORK names the workspace through a link",
			files:     map[string]string{"go.mod": gomod, "main.go": "package main\n", "go.work": "go 1.22\n\nuse .\n"},
			gowork:    "go.work",
			goworkVia: "link",
			note:      "because the workspace",
			none:      true,
		},
		{
			name:      "a relative GOWORK",
			files:     map[string]string{"go.mod": gomod, "main.go": "package main\n", "ws/go.work": "go 1.22\n\nuse ..\n"},
			gowork:    "ws/go.work",
			goworkVia: "relative",
			note:      "because the workspace ws/go.work",
			none:      true,
		},
		{
			name:   "GOWORK turns the workspace off",
			files:  map[string]string{"go.mod": gomod, "main.go": "package main\n\nimport _ \"example.com/a\"\n", "go.work": "go 1.22\n\nuse .\n"},
			gowork: "off",
			open:   []string{"example.com/gone"},
		},
		{
			name:  "a go directive before module graph pruning",
			files: map[string]string{"go.mod": "module example.com/app\n\ngo 1.16\n\nrequire example.com/a v1.0.0\n", "main.go": "package main\n"},
			note:  "its go directive is below 1.17",
			none:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			outer, cache := t.TempDir(), t.TempDir()
			dir := filepath.Join(outer, "mod")
			writeTree(t, dir, tc.files)
			if tc.outerWork != "" {
				writeTree(t, outer, map[string]string{"go.work": tc.outerWork})
			}
			writeTree(t, cache, map[string]string{
				"example.com/a@v1.0.0/a.go": "package a\n\nimport _ \"example.com/b\"\n",
				"example.com/b@v1.0.0/b.go": "package b\n",
			})
			t.Setenv("GOMODCACHE", cache)
			gowork := tc.gowork
			switch {
			case tc.goworkVia == "link":
				link := filepath.Join(t.TempDir(), "link")
				require.NoError(t, os.Symlink(dir, link))
				gowork = filepath.Join(link, gowork)
			case tc.goworkVia == "relative":
				t.Chdir(dir)
			case gowork != "" && gowork != "off":
				gowork = filepath.Join(dir, gowork)
			}
			t.Setenv("GOWORK", gowork)
			e := NewWith(dir, Options{}, nil)
			m := &model.Manifest{
				Path: "go.mod", Ecosystem: model.EcosystemGo,
				Packages: []*model.Package{goPackage("example.com/a"), goPackage("example.com/b"), goPackage("example.com/gone")},
			}
			g, err := e.Graph(context.Background(), m)
			require.NoError(t, err)
			if tc.note == "" {
				assert.Empty(t, e.Diagnostics())
			} else {
				require.Len(t, e.Diagnostics(), 1)
				assert.Contains(t, e.Diagnostics()[0].Message, tc.note)
				assert.Equal(t, CodeModuleGraph, e.Diagnostics()[0].Code)
			}
			if tc.none {
				assert.Nil(t, g)
				return
			}
			require.NotNil(t, g)
			var open []string
			for _, o := range g.Open() {
				open = append(open, o.RawName())
			}
			assert.Equal(t, tc.open, open)
			assert.Equal(t, []model.PackageVersion{m.Packages[0].ID, m.Packages[1].ID}, g.PathFrom([]model.PackageVersion{m.Packages[0].ID}, m.Packages[1].ID))
		})
	}
}

func TestGraphSkipsAnotherManifest(t *testing.T) {
	e := NewWith(t.TempDir(), Options{}, nil)
	g, err := e.Graph(context.Background(), &model.Manifest{Path: "package-lock.json", Ecosystem: model.EcosystemNpm})
	require.NoError(t, err)
	assert.Nil(t, g)
	g, err = NewWith("", Options{}, nil).Graph(context.Background(), &model.Manifest{Path: "go.mod", Ecosystem: model.EcosystemGo})
	require.NoError(t, err)
	assert.Nil(t, g, "a target with no source has no graph")
}

func TestGraphDiagnosticCountsTheOpenModulesOfEachGoMod(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{"one", "two"} {
		writeTree(t, filepath.Join(dir, sub), map[string]string{
			"go.mod":  "module example.com/" + sub + "\n\ngo 1.22\n\nrequire example.com/gone v1.0.0\n",
			"main.go": "package main\n\nimport _ \"example.com/gone\"\n",
		})
	}
	t.Setenv("GOMODCACHE", t.TempDir())
	e := NewWith(dir, Options{}, nil)
	for _, sub := range []string{"one", "two"} {
		g, err := e.Graph(context.Background(), &model.Manifest{Path: sub + "/go.mod", Ecosystem: model.EcosystemGo, Packages: []*model.Package{goPackage("example.com/gone")}})
		require.NoError(t, err)
		require.NotNil(t, g)
	}
	d := e.Diagnostics()
	require.Len(t, d, 1)
	assert.Equal(t, 2, d[0].Count)
	assert.Contains(t, d[0].Message, "vet cannot read the imports of 2 Go modules of 2 go.mod files, such as example.com/gone of one/go.mod")
}
