package cargotoml

import (
	"context"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
)

func TestPinned(t *testing.T) {
	cases := map[string]string{
		"=1.0.195":      "1.0.195",
		"= 2.0.1":       "2.0.1",
		"=1.0.0-beta.1": "1.0.0-beta.1",
		"1.0.195":       "",
		"^0.3":          "",
		"~3.8":          "",
		">=0.52, <0.60": "",
		"*":             "",
		"":              "",
	}
	for in, want := range cases {
		assert.Equal(t, want, Pinned(in), in)
	}
}

func TestExtract(t *testing.T) {
	exs := []filesystem.Extractor{New()}
	ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: "testdata/alone", Path: "Cargo.toml"}, exs)
	require.Empty(t, errs)
	require.Len(t, ms, 1)
	got := map[string]bool{}
	for _, p := range ms[0].Packages {
		got[p.ID.String()] = p.Dev
	}
	assert.Equal(t, map[string]bool{
		"cargo/serde@1.0.195": false,
		"cargo/regex":         false,
		"cargo/anything":      false,
		"cargo/futures-util":  false,
		"cargo/tempfile":      true,
		"cargo/windows-sys":   false,
	}, got, "no crate itself, no path, git or workspace dependency, and a version only for a pin")

	ms, errs = scalibr.ExtractFile(context.Background(), scalibr.File{Root: "testdata/workspace", Path: "crates/core/Cargo.toml"}, exs)
	require.Empty(t, errs)
	assert.Empty(t, ms, "the Cargo.lock of the workspace root wins")
}
