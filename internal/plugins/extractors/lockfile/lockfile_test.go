package lockfile_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
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
		{"cargo-many", "cargolock/testdata", "many-packages.lock", "Cargo.lock"},
		{"cargo-local", "cargolock/testdata", "two-packages-with-local.lock", "Cargo.lock"},
		{"pnpm-v5-peers", "pnpmlock/testdata", "peer-dependencies.yaml", "pnpm-lock.yaml"},
		{"pnpm-v6-peers", "pnpmlock/testdata", "peer-dependencies-v6.yaml", "pnpm-lock.yaml"},
		{"pnpm-v9-peers", "pnpmlock/testdata", "peer-dependencies.v9.yaml", "pnpm-lock.yaml"},
		{"pnpm-v9-groups", "pnpmlock/testdata", "mixed-groups.v9.yaml", "pnpm-lock.yaml"},
		{"yarn-v1-graph", "testdata/fixtures", "graph.v1.lock", "yarn.lock"},
		{"yarn-v2-graph", "testdata/fixtures", "graph.v2.lock", "yarn.lock"},
		{"yarn-v2-root", "yarnlock/testdata", "exclude-root.v2.lock", "yarn.lock"},
		{"bun-nested", "bunlock/testdata", "nested-dependencies.json5", "bun.lock"},
		{"bun-scoped", "bunlock/testdata", "scoped-packages-mixed.json5", "bun.lock"},
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

func TestLocalEntries(t *testing.T) {
	cases := []struct {
		file, content string
		local         []string
	}{
		{"Cargo.lock", `version = 3

[[package]]
name = "my-app"
version = "0.1.0"
dependencies = ["my-core", "serde"]

[[package]]
name = "my-core"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "abc"
`, []string{"cargo/my-app@0.1.0", "cargo/my-core@0.1.0"}},
		{"uv.lock", `version = 1
requires-python = ">=3.10"

[[package]]
name = "my-app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "my-lib" }, { name = "six" }]

[[package]]
name = "my-lib"
version = "0.2.0"
source = { editable = "packages/my-lib" }

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }
`, []string{"pypi/my-lib@0.2.0"}},
		{"yarn.lock", `# yarn lockfile v1


"eslint-plugin-internal@link:./scripts/eslint-rules":
  version "0.0.0"
  uid ""

left-pad@^1.3.0:
  version "1.3.0"
  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"
  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQ9P6smv8F8tqlSFg4pdxGFSZmwwG5h/NmtjYBPrRlOoalW8==
`, []string{"npm/eslint-plugin-internal@0.0.0"}},
	}
	exs, err := lockfile.Extractors()
	require.NoError(t, err)
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.content), 0o600))
			ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: dir, Path: tc.file}, exs)
			require.Empty(t, errs)
			require.Len(t, ms, 1)
			var local []string
			for _, p := range ms[0].Packages {
				if p.Local {
					local = append(local, p.ID.String())
				}
			}
			sort.Strings(local)
			assert.Equal(t, tc.local, local)
		})
	}
}

func TestGemfileLockPathIsLocal(t *testing.T) {
	const lock = `PATH
  remote: .
  specs:
    myapp (1.0.0)
      rack (>= 2.0)

GEM
  remote: https://rubygems.org/
  specs:
    rack (3.1.8)

DEPENDENCIES
  myapp!
`
	exs, err := lockfile.Extractors()
	require.NoError(t, err)
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "Gemfile.lock"), []byte(lock), 0o600))
	ms, errs := scalibr.ExtractFile(context.Background(), scalibr.File{Root: dir, Path: "Gemfile.lock"}, exs)
	require.Empty(t, errs)
	require.Len(t, ms, 1)
	local := map[string]bool{}
	for _, p := range ms[0].Packages {
		local[p.ID.String()] = p.Local
	}
	assert.Equal(t, map[string]bool{"rubygems/myapp@1.0.0": true, "rubygems/rack@3.1.8": false}, local)
}
