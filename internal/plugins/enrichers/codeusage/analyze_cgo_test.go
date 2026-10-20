//go:build cgo

package codeusage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/safedep/code/fileindex"
	"github.com/safedep/dry/localdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/model"
)

func write(t *testing.T, dir, rel, content string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o700))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
}

func TestDefaultAnalyzer(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.py", "import requests\nfrom yaml import safe_load\nfrom openai import OpenAI\n\nrequests.get(\"https://example.com\")\nsafe_load(\"a: 1\")\nclient = OpenAI()\n")
	write(t, dir, "node_modules/x/index.py", "import skipped\nskipped.run()\n")
	write(t, dir, "static/swagger-ui-bundle.js", "const OpenAI = require('openai');\nnew OpenAI();\n")
	write(t, dir, "static/app.min.js", "const OpenAI = require('openai');\nnew OpenAI();\n")
	a, err := newAnalyzer(Options{})(context.Background(), dir)
	require.NoError(t, err)
	var modules []string
	for _, ev := range a.Usage {
		modules = append(modules, ev.ModuleName)
		assert.Equal(t, "python", ev.Language)
	}
	assert.Contains(t, modules, "requests")
	assert.Contains(t, modules, "yaml")
	assert.NotContains(t, modules, "skipped", "installed code is not the project")

	var ids []string
	for _, m := range a.Matches {
		ids = append(ids, m.Signature.ID)
		assert.Equal(t, "app.py", m.FilePath, "safedep/code names a file relative to the target")
		assert.Equal(t, "python", m.Language)
		assert.Positive(t, m.Line)
	}
	assert.Contains(t, ids, "openai.client")
}

// A file that does not parse is a failure of that file, not of the scan.
func TestDefaultAnalyzerKeepsGoingPastAFailedFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.py", "import requests\n\nrequests.get(\"https://example.com\")\n")
	write(t, dir, "huge.py", "x = 1\n"+strings.Repeat("#", 5<<20))

	a, err := newAnalyzer(Options{})(context.Background(), dir)
	require.NoError(t, err)
	require.Len(t, a.Failed, 1)
	assert.Equal(t, "huge.py", a.Failed[0].FilePath)
	assert.Equal(t, "parse", a.Failed[0].Stage)
	var modules []string
	for _, ev := range a.Usage {
		modules = append(modules, ev.ModuleName)
	}
	assert.Contains(t, modules, "requests", "the other files still count")
}

func TestEmbeddedSignatures(t *testing.T) {
	sigs, err := loadSignatures()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(sigs), 200)
	for _, s := range sigs {
		assert.NotEmpty(t, s.GetProduct(), s.GetId())
		assert.NotEmpty(t, s.GetTags(), s.GetId())
	}
}

func TestReadSignaturesRejects(t *testing.T) {
	sig := func(id, lang, match string) string {
		return "  - id: " + id + "\n    vendor: V\n    product: P\n    languages:\n      " + lang + ":\n        match: " + match + "\n        conditions:\n          - type: call\n            value: a.b\n"
	}
	cases := map[string]fstest.MapFS{
		"duplicate id": {
			"a/x.yaml": {Data: []byte("version: 0.1\nsignatures:\n" + sig("v.p", "python", "any"))},
			"b/y.yaml": {Data: []byte("version: 0.1\nsignatures:\n" + sig("v.p", "go", "any"))},
		},
		"unknown language": {"a/x.yaml": {Data: []byte("signatures:\n" + sig("v.p", "cobol", "any"))}},
		"unknown match":    {"a/x.yaml": {Data: []byte("signatures:\n" + sig("v.p", "python", "some"))}},
		"unknown field":    {"a/x.yaml": {Data: []byte("signatures:\n  - id: v.p\n    vendr: V\n")}},
	}
	for name, fsys := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := readSignatures(fsys)
			assert.Error(t, err)
		})
	}

	ok := fstest.MapFS{"a/x.yaml": {Data: []byte("signatures:\n" + sig("v.p", "ruby", "any"))}}
	sigs, err := readSignatures(ok)
	require.NoError(t, err)
	assert.Len(t, sigs, 1)
}

func TestDefaultAnalyzerUnderSkippedParent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "build", "vendor", "app")
	write(t, dir, "app.py", "from openai import OpenAI\n\nclient = OpenAI()\n")
	write(t, dir, "vendor/x/index.py", "from openai import OpenAI\n\nOpenAI()\n")

	a, err := newAnalyzer(Options{})(context.Background(), dir)
	require.NoError(t, err)
	require.NotEmpty(t, a.Matches, "a parent directory named build or vendor is not part of the target")
	for _, m := range a.Matches {
		assert.Equal(t, "app.py", m.FilePath)
	}
}

func TestSkipPatterns(t *testing.T) {
	cases := []struct {
		root, path string
		skip       bool
	}{
		{"/ci/build/app", "/ci/build/app/main.py", false},
		{"/ci/build/app", "/ci/build/app/src/build.py", false},
		{"/ci/build/app", "/ci/build/app/node_modules/x/index.js", true},
		{"/ci/build/app", "/ci/build/app/web/dist/app.js", true},
		{"/ci/build/app", "/ci/build/app/static/swagger-ui-bundle.js", true},
		{"/ci/build/app", "/ci/build/app/internal/build/b.go", false},
		{"/ci/build/app", "/ci/build/app/build/out.js", true},
		{`C:\ci\app`, `C:\ci\app\node_modules\x\index.js`, true},
		{`C:\ci\app`, `C:\ci\app\src\index.js`, false},
	}
	for _, tc := range cases {
		skip := false
		for _, re := range skipPatterns(tc.root) {
			skip = skip || re.MatchString(tc.path)
		}
		assert.Equal(t, tc.skip, skip, tc.path)
	}
}

func testCache(t *testing.T) localdb.FileManager {
	t.Helper()
	mgr := localdb.NewFileManager(localdb.Config{Dir: t.TempDir(), FileName: "cache.db"})
	t.Cleanup(func() { assert.NoError(t, mgr.Close()) })
	return mgr
}

func TestSecondScanParsesNoFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.py", "import requests\nfrom openai import OpenAI\n\nrequests.get(\"https://example.com\")\nclient = OpenAI()\n")
	write(t, dir, "lib/util.js", "const _ = require('lodash');\n_.map([], x => x);\n")
	analyze := newAnalyzer(Options{Cache: testCache(t)})

	first, err := analyze(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]fileindex.FileStatus{"app.py": fileindex.FileIndexed, "lib/util.js": fileindex.FileIndexed}, first.Files)

	second, err := analyze(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]fileindex.FileStatus{"app.py": fileindex.FileCached, "lib/util.js": fileindex.FileCached}, second.Files)
	assert.ElementsMatch(t, first.Usage, second.Usage, "the cache gives the usage of the first scan")
	assert.ElementsMatch(t, first.Matches, second.Matches, "the cache gives the matches of the first scan")

	write(t, dir, "lib/util.js", "const _ = require('lodash');\n_.filter([], x => x);\n")
	third, err := analyze(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]fileindex.FileStatus{"app.py": fileindex.FileCached, "lib/util.js": fileindex.FileIndexed}, third.Files, "a changed file parses again")
}

func TestUsageLineIsTheImport(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.py", "import os\nimport requests\n\n\nrequests.get(\"https://example.com\")\n")
	a, err := newAnalyzer(Options{})(context.Background(), dir)
	require.NoError(t, err)
	for _, ev := range a.Usage {
		if ev.ModuleName == "requests" {
			assert.Equal(t, uint(2), ev.Line)
		}
	}
}

// A deadline that ends before the walk gives no files, and a late one gives
// none missing, so the test tries longer deadlines until one stops the run
// after some files and before the others.
func TestDeadlineMakesFilesMissing(t *testing.T) {
	dir := t.TempDir()
	body := strings.Repeat("requests.get(\"https://example.com\")\n", 3000)
	for i := range 100 {
		write(t, dir, fmt.Sprintf("m%03d.py", i), "import requests\n"+body)
	}
	for d := time.Millisecond; d < 10*time.Second; d *= 2 {
		ctx, cancel := context.WithTimeout(context.Background(), d)
		a, err := newAnalyzer(Options{})(ctx, dir)
		cancel()
		if err == nil {
			break
		}
		require.ErrorIs(t, err, context.DeadlineExceeded)
		counts := map[fileindex.FileStatus]int{}
		for _, st := range a.Files {
			counts[st]++
		}
		if len(a.Files) == 100 && counts[fileindex.FileMissing] > 0 && counts[fileindex.FileIndexed] > 0 {
			assert.Empty(t, a.Failed, "a file that the deadline cuts is missing, not failed")
			return
		}
	}
	t.Fatal("no deadline stopped the analysis in the parse")
}

func TestPruneIndex(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.py", "import requests\nrequests.get(\"https://example.com\")\n")
	cache := testCache(t)
	_, err := newAnalyzer(Options{Cache: cache})(context.Background(), dir)
	require.NoError(t, err)

	n, err := PruneIndex(context.Background(), cache, time.Now())
	require.NoError(t, err)
	assert.Zero(t, n, "a file read now stays")
	n, err = PruneIndex(context.Background(), cache, time.Now().Add(indexRetention+time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 2, n, "the index and the analysis of the file go")
}

func TestModuleVersion(t *testing.T) {
	const code = "github.com/safedep/code"
	cases := map[string]struct {
		info *debug.BuildInfo
		want string
	}{
		"no build info": {nil, "unknown"},
		"a pinned version": {&debug.BuildInfo{Deps: []*debug.Module{
			{Path: "github.com/other/mod", Version: "v1.0.0"},
			{Path: code, Version: "v0.0.0-20261019105110-16bd15970d6e"},
		}}, "v0.0.0-20261019105110-16bd15970d6e"},
		"a replaced module": {&debug.BuildInfo{Deps: []*debug.Module{
			{Path: code, Version: "v0.0.1", Replace: &debug.Module{Path: "../code", Version: "", Sum: ""}},
		}}, "../code@"},
		"no such module": {&debug.BuildInfo{}, "unknown"},
	}
	for name, c := range cases {
		assert.Equal(t, c.want, moduleVersion(c.info, code), name)
	}
}

func TestFirstUses(t *testing.T) {
	evs := []Evidence{
		{ModuleName: "a", FilePath: "x.py", Line: 9},
		{ModuleName: "a", FilePath: "x.py", Line: 3},
		{ModuleName: "b", FilePath: "x.py", Line: 5},
		{ModuleName: "a", FilePath: "x.py", Line: 7},
	}
	assert.Equal(t, []Evidence{
		{ModuleName: "a", FilePath: "x.py", Line: 3},
		{ModuleName: "b", FilePath: "x.py", Line: 5},
	}, firstUses(evs))
}

func TestBrokenCacheParsesEveryFile(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.py", "import requests\nrequests.get(\"https://example.com\")\n")
	notADir := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0o600))
	broken := localdb.NewFileManager(localdb.Config{Dir: notADir, FileName: "cache.db"})
	a, err := newAnalyzer(Options{Cache: broken})(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]fileindex.FileStatus{"app.py": fileindex.FileIndexed}, a.Files)
}

func TestComputedImportIsDynamic(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.py", "import importlib\nname = input()\nmod = importlib.import_module(name)\n")
	write(t, dir, "lib.js", "const a = require('lodash');\n")
	a, err := newAnalyzer(Options{})(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{"python": true}, a.DynamicImports)
}

func TestUsageCallsAndDynamicSites(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "app.py", "import yaml\n\nyaml.load(x)\n")
	write(t, dir, "plugins.py", "import importlib\nimport yaml\n\nmod = importlib.import_module(name)\nyaml.dump(mod)\n")
	write(t, dir, "main.go", "package main\n\nimport \"golang.org/x/net/html\"\n\nfunc main() {\n\thtml.Render(w, n)\n}\n")
	write(t, dir, "src/main.rs", "fn main() {\n    let now = time::OffsetDateTime::now_local();\n}\n")
	e := New(Options{})
	e.UseSource(dir)
	yaml := &model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, "PyYAML", "6.0")}
	net := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, "golang.org/x/net", "v0.20.0")}
	tm := &model.Package{ID: model.MustPackageVersion(model.EcosystemCargo, "time", "0.3.30")}
	require.NoError(t, e.Enrich(context.Background(), []*model.Package{yaml, net, tm}))

	require.NotNil(t, yaml.Usage)
	assert.Equal(t, []model.CallSite{{File: "app.py", Line: 3, Callee: "yaml//load"}, {File: "plugins.py", Line: 5, Callee: "yaml//dump"}}, yaml.Usage.Calls)
	assert.Equal(t, []model.DynamicSite{{File: "plugins.py", Line: 4, Kind: "computed-import"}}, yaml.Usage.Dynamic,
		"the dynamic sites come from the files that import the package")
	require.NotNil(t, net.Usage)
	assert.Equal(t, []model.CallSite{{File: "main.go", Line: 6, Callee: "golang.org//x//net//html//Render"}}, net.Usage.Calls)
	require.NotNil(t, tm.Usage)
	assert.Contains(t, tm.Usage.Calls, model.CallSite{File: "src/main.rs", Line: 2, Callee: "time//OffsetDateTime//now_local"})
}

func TestUnreadFileAndUnknownExtension(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "App.jsx", "import pad from 'left-pad';\npad('x', 3);\n")
	write(t, dir, "big.py", "import yaml\n"+strings.Repeat("#", 5<<20))
	a, err := newAnalyzer(Options{})(context.Background(), dir)
	require.NoError(t, err)
	assert.True(t, a.Unread["python"], "a Python file over the size limit is unread")
	assert.False(t, a.Languages["javascript"], "vet parses no .jsx file")
}

// The key of a fix site must equal the call target that safedep/code gives
// the same function, or function reach never finds a call.
func TestSymbolKeyMatchesTheCallGraph(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "main.go", "package main\n\nimport (\n\t\"net/http\"\n\n\t\"golang.org/x/net/html\"\n)\n\nfunc main() {\n\thtml.Render(w, n)\n\thttp.ServeContent(w, r, name, t, f)\n}\n")
	write(t, dir, "src/main.rs", "fn main() {\n    let now = time::OffsetDateTime::now_local();\n}\n")
	a, err := newAnalyzer(Options{})(context.Background(), dir)
	require.NoError(t, err)
	var targets []string
	for _, c := range a.Calls {
		targets = append(targets, c.Callee)
	}
	for _, row := range []struct{ language, name string }{
		{"go", "golang.org/x/net/html.Render"},
		{"go", "net/http.ServeContent"},
		{"rust", "time::OffsetDateTime::now_local"},
	} {
		assert.Contains(t, targets, SymbolKey(row.language, row.name), row.name)
	}
}

// A vendored module gives the call graph the code of the dependency, so a
// call into a function that calls the fix site is a path.
func TestReachThroughVendoredCode(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.mod", "module example.com/app\n\ngo 1.27\n\nrequire example.com/dep v1.2.0\n")
	write(t, dir, "main.go", "package main\n\nimport \"example.com/dep/html\"\n\nfunc main() {\n\thtml.Parse(nil)\n}\n\nfunc handle() {\n\thtml.Unused()\n}\n")
	write(t, dir, "vendor/modules.txt", "# example.com/dep v1.2.0\n## explicit\nexample.com/dep/html\n")
	write(t, dir, "vendor/example.com/dep/html/parse.go", "package html\n\nfunc Parse(b []byte) { render(b) }\n\nfunc render(b []byte) {}\n\nfunc Unused() {}\n\nfunc Tested() {}\n")
	write(t, dir, "main_test.go", "package main\n\nimport (\n\t\"testing\"\n\n\t\"example.com/dep/html\"\n)\n\nfunc TestTested(t *testing.T) {\n\thtml.Tested()\n}\n")
	t.Setenv("GOMODCACHE", t.TempDir())
	a, err := newAnalyzer(Options{})(context.Background(), dir)
	require.NoError(t, err)
	require.NotNil(t, a.Reach)
	unit, ok := unitOf(dir, model.MustPackageVersion(model.EcosystemGo, "example.com/dep", "v1.2.0"))
	require.True(t, ok)
	render, unused := SymbolKey("go", "example.com/dep/html.render"), SymbolKey("go", "example.com/dep/html.Unused")
	res, err := a.Reach(context.Background(), ReachQuery{Units: []Unit{unit}, Targets: []string{render, unused}})
	require.NoError(t, err)
	assert.Equal(t, ReachFound, res.Answers[render].Status, "main calls Parse, and Parse calls render")
	require.NotEmpty(t, res.Answers[render].Path)
	assert.Equal(t, "main", res.Answers[render].Path[0].Root)
	assert.Equal(t, ReachNotFound, res.Answers[unused].Status)
	require.NotNil(t, res.Roots)

	tested := SymbolKey("go", "example.com/dep/html.Tested")
	testRes, err := a.Reach(context.Background(), ReachQuery{Units: []Unit{unit}, Targets: []string{tested}})
	require.NoError(t, err)
	assert.Equal(t, ReachAnswer{Status: ReachFound, TestOnly: true, Path: testRes.Answers[tested].Path}, testRes.Answers[tested], "a path from a test only is a call")
	require.NotEmpty(t, testRes.Answers[tested].Path)
	assert.False(t, res.Roots.Fallback)
	assert.NotEmpty(t, res.Roots.List)

	res, err = a.Reach(context.Background(), ReachQuery{Units: []Unit{unit}, Targets: []string{unused}, Sources: []string{"main.go:handle"}})
	require.NoError(t, err)
	require.Equal(t, ReachFound, res.Answers[unused].Status, "a named entry point reaches what main does not")
	assert.Equal(t, "query", res.Answers[unused].Path[0].Root)

	res, err = a.Reach(context.Background(), ReachQuery{Targets: []string{render}})
	require.NoError(t, err)
	assert.NotEqual(t, ReachNotFound, res.Answers[render].Status, "with no code of the dependency, no path proves nothing")

	_, err = a.Reach(context.Background(), ReachQuery{Units: []Unit{unit}, Targets: []string{render}, Sources: []string{"main.go:nope"}})
	assert.Equal(t, app.ExitUsage, app.ExitCode(err), "an entry point that names no function is a usage error")
}

// A library with no main has no entry point of its own. No path in it is
// never a proof.
func TestReachOfALibraryWithNoMain(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.mod", "module example.com/lib\n\ngo 1.27\n\nrequire example.com/dep v1.2.0\n")
	write(t, dir, "lib.go", "package lib\n\nimport \"example.com/dep/html\"\n\nfunc Run() {\n\thtml.Parse(nil)\n}\n")
	write(t, dir, "vendor/modules.txt", "# example.com/dep v1.2.0\n## explicit\nexample.com/dep/html\n")
	write(t, dir, "vendor/example.com/dep/html/parse.go", "package html\n\nfunc Parse(b []byte) {}\n\nfunc Unused() {}\n")
	t.Setenv("GOMODCACHE", t.TempDir())
	a, err := newAnalyzer(Options{})(context.Background(), dir)
	require.NoError(t, err)
	unit, ok := unitOf(dir, model.MustPackageVersion(model.EcosystemGo, "example.com/dep", "v1.2.0"))
	require.True(t, ok)
	unused := SymbolKey("go", "example.com/dep/html.Unused")
	res, err := a.Reach(context.Background(), ReachQuery{Units: []Unit{unit}, Targets: []string{unused}})
	require.NoError(t, err)
	require.NotNil(t, res.Roots)
	assert.True(t, res.Roots.Fallback)
	got := functionReachOf(&model.SymbolRecord{Coverage: model.CoverageExact, Verified: true, Keys: []string{unused}}, res.Answers, true, "")
	assert.Equal(t, &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachNoEntryPoint)}, got)
}

// A package of the project can have the name build. Only a build directory
// directly under the target holds built code.
func TestBuildPackageOfTheProjectIsCode(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.mod", "module example.com/app\n\ngo 1.27\n")
	write(t, dir, "internal/build/b.go", "package build\n\nimport \"example.com/dep/html\"\n\nfunc B() { html.Render(nil) }\n")
	write(t, dir, "build/out.go", "package out\n\nimport \"example.com/dep/html\"\n")
	a, err := newAnalyzer(Options{})(context.Background(), dir)
	require.NoError(t, err)
	assert.Contains(t, a.Files, "internal/build/b.go")
	assert.NotContains(t, a.Files, "build/out.go")
}

// A file that names a package only in a type still imports it.
func TestTypeOnlyGoImportIsAnImport(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "go.mod", "module example.com/app\n\ngo 1.27\n")
	write(t, dir, "main.go", "package main\n\nimport \"example.com/dep/html\"\n\nvar t *html.Tokenizer\n\nfunc main() {}\n")
	a, err := newAnalyzer(Options{})(context.Background(), dir)
	require.NoError(t, err)
	var mods []string
	for _, ev := range a.Usage {
		mods = append(mods, ev.ModuleName)
	}
	assert.Contains(t, mods, "example.com/dep/html")
}
