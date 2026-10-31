package gomod

import (
	"context"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
)

func TestStdlib(t *testing.T) {
	e, err := New()
	require.NoError(t, err)
	cases := []struct {
		dir  string
		want []string
	}{
		{"directive", []string{"go/golang.org/x/text@0.14.0"}},
		{"toolchain", []string{"go/golang.org/x/text@0.14.0", "go/stdlib@1.23.4"}},
	}
	for _, tc := range cases {
		t.Run(tc.dir, func(t *testing.T) {
			ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: "testdata/" + tc.dir, Path: "go.mod"}, []filesystem.Extractor{e})
			require.Empty(t, errs)
			require.Len(t, ms, 1)
			var got []string
			for _, p := range ms[0].Packages {
				got = append(got, p.ID.String())
			}
			assert.ElementsMatch(t, tc.want, got)
		})
	}
}

func TestReplaceRecordsTheModuleThatTheCodeImports(t *testing.T) {
	e, err := New()
	require.NoError(t, err)
	ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: "testdata/replace", Path: "go.mod"}, []filesystem.Extractor{e})
	require.Empty(t, errs)
	require.Len(t, ms, 1)
	got := map[string]string{}
	for _, p := range ms[0].Packages {
		got[p.ID.String()] = p.Replaces
	}
	assert.Equal(t, map[string]string{
		"go/example.com/fork@1.1.0":  "example.com/upstream",
		"go/example.com/plain@1.2.0": "",
	}, got, "a local replacement is no package")
}

func TestVendorReplaceRecordsTheModuleThatTheCodeImports(t *testing.T) {
	e, err := NewVendor()
	require.NoError(t, err)
	ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: "testdata/vendor", Path: "vendor/modules.txt"}, []filesystem.Extractor{e})
	require.Empty(t, errs)
	require.Len(t, ms, 1)
	got := map[string]string{}
	for _, p := range ms[0].Packages {
		got[p.ID.String()] = p.Replaces
	}
	assert.Equal(t, map[string]string{
		"go/example.com/fork@1.1.0":  "example.com/upstream",
		"go/example.com/other@0.3.0": "example.com/noversion",
		"go/example.com/local@1.0.0": "",
		"go/example.com/plain@1.2.0": "",
	}, got)
}
