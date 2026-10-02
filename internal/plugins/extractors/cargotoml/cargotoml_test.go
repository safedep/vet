package cargotoml

import (
	"context"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
)

func TestFloor(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"1.0.195", "1.0.195", true},
		{"1.10", "1.10.0", true},
		{"1", "1.0.0", true},
		{"^0.3", "0.3.0", true},
		{"~3.8", "3.8.0", true},
		{"=2.0.1", "2.0.1", true},
		{">=0.52, <0.60", "0.52.0", true},
		{"1.2.*", "1.2.0", true},
		{"1.0.0-alpha.1", "1.0.0-alpha.1", true},
		{"*", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := Floor(tc.in)
		assert.Equal(t, tc.ok, ok, tc.in)
		assert.Equal(t, tc.want, got, tc.in)
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
		"cargo/serde@1.0.195":      false,
		"cargo/regex@1.10.0":       false,
		"cargo/futures-util@0.3.0": false,
		"cargo/tempfile@3.8.0":     true,
		"cargo/windows-sys@0.52.0": false,
	}, got, "no crate itself, no path, git, workspace or wildcard dependency")

	ms, errs = scalibr.ExtractFile(context.Background(), scalibr.File{Root: "testdata/workspace", Path: "crates/core/Cargo.toml"}, exs)
	require.Empty(t, errs)
	assert.Empty(t, ms, "the Cargo.lock of the workspace root wins")
}
