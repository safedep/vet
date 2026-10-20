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

	"github.com/safedep/dry/localdb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	assert.Equal(t, map[string]string{"app.py": "indexed", "lib/util.js": "indexed"}, first.Files)

	second, err := analyze(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"app.py": "cached", "lib/util.js": "cached"}, second.Files)
	assert.ElementsMatch(t, first.Usage, second.Usage, "the cache gives the usage of the first scan")
	assert.ElementsMatch(t, first.Matches, second.Matches, "the cache gives the matches of the first scan")

	write(t, dir, "lib/util.js", "const _ = require('lodash');\n_.filter([], x => x);\n")
	third, err := analyze(context.Background(), dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{"app.py": "cached", "lib/util.js": "indexed"}, third.Files, "a changed file parses again")
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
// in the parse.
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
		missing := 0
		for _, st := range a.Files {
			if st == FileMissing {
				missing++
			}
		}
		if len(a.Files) == 100 && missing > 0 {
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
