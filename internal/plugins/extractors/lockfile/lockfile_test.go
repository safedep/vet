package lockfile_test

import (
	"context"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/golden"
	"github.com/safedep/vet/v2/internal/plugins/extractors/lockfile"
	"github.com/safedep/vet/v2/internal/plugins/extractors/scalibr"
	"github.com/safedep/vet/v2/model"
)

// graphView is the dependency graph of a manifest for a golden file.
type graphView struct {
	Packages []string `json:"packages"`
	Direct   []string `json:"direct"`
	Dev      []string `json:"dev,omitempty"`
	Roots    []string `json:"roots"`
	Edges    []string `json:"edges"`
}

func viewOf(m *model.Manifest) graphView {
	v := graphView{Packages: []string{}, Direct: []string{}, Roots: []string{}, Edges: []string{}}
	for _, p := range m.Packages {
		v.Packages = append(v.Packages, p.ID.String())
		if p.Direct {
			v.Direct = append(v.Direct, p.ID.String())
		}
		if p.Dev {
			v.Dev = append(v.Dev, p.ID.String())
		}
	}
	if m.Graph != nil {
		for _, r := range m.Graph.Roots() {
			v.Roots = append(v.Roots, r.String())
		}
		m.Graph.Edges(func(p, c model.PackageID) { v.Edges = append(v.Edges, p.String()+" -> "+c.String()) })
	}
	for _, s := range [][]string{v.Packages, v.Direct, v.Dev, v.Roots, v.Edges} {
		sort.Strings(s)
	}
	return v
}

// TestGraphGolden runs each vet lockfile extractor through the adapter on
// upstream fixtures, and checks the graph against a golden file.
func TestGraphGolden(t *testing.T) {
	exs, err := lockfile.Extractors()
	require.NoError(t, err)

	cases := []struct {
		name, dir, file, as string
	}{
		{"npm-nested", "packagelockjson/testdata", "nested-dependencies.v2.json", "package-lock.json"},
		{"npm-nested-dup", "packagelockjson/testdata", "nested-dependencies-dup.v2.json", "package-lock.json"},
		{"npm-dev", "packagelockjson/testdata", "one-package-dev.v2.json", "package-lock.json"},
		{"npm-workspaces", "packagelockjson/testdata", "workspaces.v3.json", "package-lock.json"},
		{"uv-two", "uvlock/testdata", "two-packages.lock", "uv.lock"},
		{"uv-grouped", "uvlock/testdata", "grouped-packages.lock", "uv.lock"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			copyFile(t, filepath.Join(tc.dir, tc.file), filepath.Join(root, tc.as))
			ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: root, Path: tc.as}, exs)
			require.Empty(t, errs)
			require.Len(t, ms, 1)
			golden.AssertJSON(t, filepath.Join("testdata", "golden", tc.name+".json"), viewOf(ms[0]))
		})
	}
}
