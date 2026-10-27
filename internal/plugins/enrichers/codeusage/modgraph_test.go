package codeusage

import (
	"cmp"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/safedep/code/modgraph"
	"github.com/safedep/dry/localdb"
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
		// testImports are the imports of a test file of the main module.
		testImports []string
		modules     []modgraph.Source
		pkgs        []*model.Package
		roots       []string
		testRoots   []string
		edges       []edge
		open        []string
		why         string
		// notRequired names modules of the build list that go.mod does not
		// require, as a workspace adds them.
		notRequired []string
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
			name:    "a module that go.mod does not require passes its imports on",
			imports: []string{"example.com/a"},
			modules: []modgraph.Source{
				goSource("example.com/a", fstest.MapFS{"a.go": goFile("a", "example.com/extra")}),
				goSource("example.com/extra", fstest.MapFS{"e.go": goFile("e", "example.com/x")}),
				goSource("example.com/x", fstest.MapFS{"x.go": goFile("x")}),
			},
			pkgs:        []*model.Package{goPackage("example.com/a"), goPackage("example.com/x")},
			notRequired: []string{"example.com/extra"},
			roots:       []string{"example.com/a"},
			edges:       []edge{{"example.com/a", "example.com/x"}},
		},
		{
			name:        "a module that only a test file imports is a test root",
			imports:     []string{"example.com/a"},
			testImports: []string{"example.com/a", "example.com/t"},
			modules: []modgraph.Source{
				goSource("example.com/a", fstest.MapFS{"a.go": goFile("a")}),
				goSource("example.com/t", fstest.MapFS{"t.go": goFile("t")}),
			},
			pkgs:      []*model.Package{goPackage("example.com/a"), goPackage("example.com/t")},
			roots:     []string{"example.com/a", "example.com/t"},
			testRoots: []string{"example.com/t"},
		},
		{
			name:        "a local module that only a test file imports passes on a test root",
			testImports: []string{"example.com/local"},
			modules: []modgraph.Source{
				localSource("example.com/local", fstest.MapFS{"l.go": goFile("l", "example.com/x")}),
				goSource("example.com/x", fstest.MapFS{"x.go": goFile("x")}),
			},
			pkgs:      []*model.Package{goPackage("example.com/x")},
			roots:     []string{"example.com/x"},
			testRoots: []string{"example.com/x"},
		},
		{
			name:        "a test import of a root that a local module also imports",
			imports:     []string{"example.com/local"},
			testImports: []string{"example.com/x"},
			modules: []modgraph.Source{
				localSource("example.com/local", fstest.MapFS{"l.go": goFile("l", "example.com/x")}),
				goSource("example.com/x", fstest.MapFS{"x.go": goFile("x")}),
			},
			pkgs:  []*model.Package{goPackage("example.com/x")},
			roots: []string{"example.com/x"},
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
			if tc.testImports != nil {
				main["main_test.go"] = goFile("main", tc.testImports...)
			}
			g, err := modgraph.Build(context.Background(), modgraph.Input{MainFS: main, Modules: tc.modules})
			require.NoError(t, err)
			required := map[string]bool{}
			for _, m := range tc.modules {
				required[m.Module.Path] = !slices.Contains(tc.notRequired, m.Module.Path)
			}
			got, why := moduleGraph(g, tc.pkgs, localReplacements(tc.modules), required)
			if tc.why != "" {
				assert.Nil(t, got)
				assert.Contains(t, why, tc.why)
				return
			}
			require.Empty(t, why)
			require.NotNil(t, got)
			assert.True(t, got.Imports())
			var roots, testRoots, open []string
			for _, r := range got.Roots() {
				roots = append(roots, r.RawName())
			}
			for _, r := range got.TestRoots() {
				testRoots = append(testRoots, r.RawName())
			}
			for _, o := range got.Open() {
				open = append(open, o.RawName())
			}
			var edges []edge
			got.Edges(func(p, c model.PackageVersion) { edges = append(edges, edge{p.RawName(), c.RawName()}) })
			assert.Equal(t, tc.roots, roots)
			assert.Equal(t, tc.testRoots, testRoots)
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
	// A workspace needs the go.mod of each module that it requires.
	const wsMod = "module example.com/app\n\ngo 1.22\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n)\n"
	const wsMain = "package main\n\nimport _ \"example.com/a\"\n"
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
		roots     []string
		// manifest is the path of the manifest, go.mod when empty.
		manifest string
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
			files: map[string]string{"go.mod": wsMod, "main.go": wsMain, "go.work": "go 1.22\n\nuse .\n"},
			roots: []string{"example.com/a"},
		},
		{
			name: "another module of the workspace passes its imports on",
			files: map[string]string{
				"go.mod": wsMod, "main.go": "package main\n\nimport (\n\t_ \"example.com/a\"\n\t_ \"example.com/lib\"\n)\n",
				"go.work":    "go 1.22\n\nuse .\nuse ./lib\n",
				"lib/go.mod": "module example.com/lib\n\ngo 1.22\n\nrequire example.com/b v1.0.0\n",
				"lib/lib.go": "package lib\n\nimport _ \"example.com/b\"\n",
			},
			roots: []string{"example.com/a", "example.com/b"},
		},
		{
			name:  "a workspace whose build list is not on the disk",
			files: map[string]string{"go.mod": gomod, "main.go": wsMain, "go.work": "go 1.22\n\nuse .\n"},
			note:  "no go.mod of example.com/gone@v1.0.0 is on the disk",
			none:  true,
		},
		{
			name:  "a workspace that does not use the module",
			files: map[string]string{"go.mod": gomod, "main.go": "package main\n\nimport _ \"example.com/a\"\n", "go.work": "go 1.22\n\nuse ./other\n"},
			open:  []string{"example.com/gone"},
		},
		{
			name:   "GOWORK names a workspace that uses the module",
			files:  map[string]string{"go.mod": wsMod, "main.go": wsMain, "ws/go.work": "go 1.22\n\nuse ..\n"},
			gowork: "ws/go.work",
			roots:  []string{"example.com/a"},
		},
		{
			name:      "a workspace above the scan root",
			files:     map[string]string{"go.mod": wsMod, "main.go": wsMain},
			outerWork: "go 1.22\n\nuse ./mod\n",
			roots:     []string{"example.com/a"},
		},
		{
			name:      "GOWORK names the workspace through a link",
			files:     map[string]string{"go.mod": wsMod, "main.go": wsMain, "go.work": "go 1.22\n\nuse .\n"},
			gowork:    "go.work",
			goworkVia: "link",
			roots:     []string{"example.com/a"},
		},
		{
			name:      "a relative GOWORK",
			files:     map[string]string{"go.mod": wsMod, "main.go": wsMain, "ws/go.work": "go 1.22\n\nuse ..\n"},
			gowork:    "ws/go.work",
			goworkVia: "relative",
			note:      "GOWORK=ws/go.work is not an absolute path",
			none:      true,
		},
		{
			name:   "GOWORK turns the workspace off",
			files:  map[string]string{"go.mod": gomod, "main.go": "package main\n\nimport _ \"example.com/a\"\n", "go.work": "go 1.22\n\nuse .\n"},
			gowork: "off",
			open:   []string{"example.com/gone"},
		},
		{
			name: "the vendor list of a module gets the graph of its go.mod",
			files: map[string]string{
				"go.mod": wsMod, "main.go": wsMain,
				"vendor/modules.txt":        "# example.com/a v1.0.0\n## explicit\nexample.com/a\n# example.com/b v1.0.0\n## explicit\nexample.com/b\n",
				"vendor/example.com/a/a.go": "package a\n\nimport _ \"example.com/b\"\n",
				"vendor/example.com/b/b.go": "package b\n",
			},
			manifest: "vendor/modules.txt",
			roots:    []string{"example.com/a"},
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
				"example.com/a@v1.0.0/a.go":                  "package a\n\nimport _ \"example.com/b\"\n",
				"example.com/b@v1.0.0/b.go":                  "package b\n",
				"cache/download/example.com/a/@v/v1.0.0.mod": "module example.com/a\n\ngo 1.22\n\nrequire example.com/b v1.0.0\n",
				"cache/download/example.com/b/@v/v1.0.0.mod": "module example.com/b\n\ngo 1.22\n",
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
				Path: cmp.Or(tc.manifest, "go.mod"), Ecosystem: model.EcosystemGo,
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
			if tc.roots != nil {
				var roots []string
				for _, r := range g.Roots() {
					roots = append(roots, r.RawName())
				}
				assert.Equal(t, tc.roots, roots)
			}
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

func TestGraphReadsTheModuleCacheOfAnEarlierScan(t *testing.T) {
	dir, cache := t.TempDir(), t.TempDir()
	writeTree(t, dir, map[string]string{
		"go.mod":  "module example.com/app\n\ngo 1.22\n\nrequire (\n\texample.com/a v1.0.0\n\texample.com/b v1.0.0\n)\n",
		"main.go": "package main\n\nimport _ \"example.com/a\"\n",
	})
	writeTree(t, cache, map[string]string{
		"example.com/a@v1.0.0/a.go": "package a\n\nimport _ \"example.com/b\"\n",
		"example.com/b@v1.0.0/b.go": "package b\n",
	})
	t.Setenv("GOMODCACHE", cache)
	t.Setenv("GOWORK", "off")
	db := localdb.NewFileManager(localdb.Config{Dir: t.TempDir(), FileName: "cache.db"})
	t.Cleanup(func() { assert.NoError(t, db.Close()) })
	m := &model.Manifest{Path: "go.mod", Ecosystem: model.EcosystemGo, Packages: []*model.Package{goPackage("example.com/a"), goPackage("example.com/b")}}

	first, err := NewWith(dir, Options{Cache: db}, nil).Graph(context.Background(), m)
	require.NoError(t, err)
	require.NotNil(t, first)
	// A module version of the module cache never changes, so the second
	// scan takes the imports of a from the cache, not from the edited file.
	writeTree(t, cache, map[string]string{"example.com/a@v1.0.0/a.go": "package a\n"})
	second, err := NewWith(dir, Options{Cache: db}, nil).Graph(context.Background(), m)
	require.NoError(t, err)
	require.NotNil(t, second)
	assert.Equal(t, first.Roots(), second.Roots())
	assert.Equal(t, []model.PackageVersion{m.Packages[1].ID}, second.Children(m.Packages[0].ID))
}
