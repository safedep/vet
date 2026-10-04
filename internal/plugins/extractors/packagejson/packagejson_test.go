package packagejson

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/golden"
	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
)

func TestFloor(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"^4.18.2", "4.18.2", true},
		{"~1.3.0", "1.3.0", true},
		{"4.17.21", "4.17.21", true},
		{">=29.0.0 <30", "29.0.0", true},
		{"1.0.0-beta.1", "1.0.0-beta.1", true},
		{"*", "", false},
		{"latest", "", false},
		{"file:../lib", "", false},
		{"github:user/repo#v1.2.3", "", false},
		{"https://example.com/x-1.0.0.tgz", "", false},
		{"workspace:^1.0.0", "", false},
	}
	for _, tc := range cases {
		got, ok := Floor(tc.in)
		assert.Equal(t, tc.ok, ok, tc.in)
		assert.Equal(t, tc.want, got, tc.in)
	}
}

func TestExtract(t *testing.T) {
	exs := []filesystem.Extractor{New()}
	ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: "testdata/alone", Path: "package.json"}, exs)
	require.Empty(t, errs)
	require.Len(t, ms, 1)
	golden.AssertJSON(t, filepath.Join("testdata", "golden", "alone.json"), ms[0].Packages)
	for _, p := range ms[0].Packages {
		assert.True(t, p.Direct)
		assert.Equal(t, p.ID.Name == "jest", p.Dev, p.ID.Name)
	}

	ms, errs = scalibr.ExtractFile(context.Background(), scalibr.File{Root: "testdata/locked", Path: "package.json"}, exs)
	require.Empty(t, errs)
	assert.Empty(t, ms, "a lockfile next to package.json wins")
}

func TestFileRequired(t *testing.T) {
	e := New()
	assert.True(t, e.FileRequired(simpleAPI("package.json")))
	assert.True(t, e.FileRequired(simpleAPI("web/package.json")))
	assert.False(t, e.FileRequired(simpleAPI("node_modules/x/package.json")))
	assert.False(t, e.FileRequired(simpleAPI("package-lock.json")))
}
