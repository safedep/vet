//go:build cgo

package codeusage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

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
	a, err := defaultAnalyzer(context.Background(), dir)
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
		assert.Equal(t, filepath.Join(dir, "app.py"), m.FilePath)
		assert.Equal(t, "python", m.Language)
		assert.Positive(t, m.Line)
	}
	assert.Contains(t, ids, "openai.client")
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
