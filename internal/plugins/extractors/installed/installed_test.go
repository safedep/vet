package installed

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackageRoot(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"node_modules/left-pad/package.json", true},
		{"app/node_modules/@scope/x/package.json", true},
		{"node_modules/a/node_modules/b/package.json", true},
		{"node_modules/.pnpm/c@1.0.0/node_modules/c/package.json", true},
		{"node_modules/.pnpm/@s+x@1.0.0/node_modules/@s/x/package.json", true},
		{"package.json", false},
		{"node_modules/package.json", false},
		{"node_modules/minimist/test/fixture/package.json", false},
		{"node_modules/serve/benchmark/package.json", false},
		{"node_modules/left-pad/index.js", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			assert.Equal(t, tc.want, packageRoot(tc.path))
		})
	}
}

func TestInInstallDir(t *testing.T) {
	assert.True(t, InInstallDir("node_modules/x/package.json"))
	assert.True(t, InInstallDir("usr/lib/python3/dist-packages/x/requirements.txt"))
	assert.True(t, InInstallDir(".venv/lib/python3.12/site-packages/x/pyproject.toml"))
	assert.False(t, InInstallDir("package.json"))
	assert.False(t, InInstallDir("app/package-lock.json"))
	assert.False(t, InInstallDir("my_node_modules/package.json"))
}

// TestGoBinaryStdlib reads the test binary, which is a Go binary with build
// information and no dependency list.
func TestGoBinaryStdlib(t *testing.T) {
	exe, err := os.Executable()
	require.NoError(t, err)
	gb := find[goBinary](t)

	f, err := os.Open(exe)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, f.Close()) })
	info, err := f.Stat()
	require.NoError(t, err)
	inv, err := gb.Extract(context.Background(), &filesystem.ScanInput{
		FS: scalibrfs.DirFS("/"), Path: exe, Root: "/", Reader: f, Info: info,
	})
	require.NoError(t, err)
	var names []string
	for _, p := range inv.Packages {
		names = append(names, p.Name)
	}
	assert.Equal(t, []string{"stdlib"}, names, "the toolchain is stdlib, and the main module of a test build has no release version")
}

func TestReleased(t *testing.T) {
	cases := map[string]bool{
		"v1.2.3":                               true,
		"v2.0.0-alpha.1":                       true,
		"(devel)":                              false,
		"":                                     false,
		"v0.0.0-20261005161535-bf6a2ae24b1b":   false,
		"v1.2.4-0.20261005161535-bf6a2ae24b1b": false,
		"v1.2.3+dirty":                         false,
	}
	for v, want := range cases {
		assert.Equal(t, want, released(v), v)
	}
}

func TestPythonDistInInstallDirOnly(t *testing.T) {
	p := find[pythonDist](t)
	assert.True(t, p.FileRequired(fileAPI(t, ".venv/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA")))
	assert.False(t, p.FileRequired(fileAPI(t, "app.egg-info/PKG-INFO")), "the egg-info of an editable install is the project")
	assert.False(t, p.FileRequired(fileAPI(t, "dist/app-1.0.0-py3-none-any.whl")), "a wheel in dist/ is the project")
}

// TestRustBinaryDropsRoot reads the cargo-auditable test binary of Scalibr.
// Its root crate is uses_json 0.1.0.
func TestRustBinaryDropsRoot(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/google/osv-scalibr").Output()
	require.NoError(t, err)
	bin := filepath.Join(strings.TrimSpace(string(out)), "extractor/filesystem/language/rust/cargoauditable/testdata/uses_serde_json/uses_serde_json")
	f, err := os.Open(bin)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, f.Close()) })
	info, err := f.Stat()
	require.NoError(t, err)

	inv, err := find[rustBinary](t).Extract(context.Background(), &filesystem.ScanInput{Path: bin, Reader: f, Info: info})
	require.NoError(t, err)
	var names []string
	for _, p := range inv.Packages {
		names = append(names, p.Name)
	}
	assert.Contains(t, names, "serde_json")
	assert.NotContains(t, names, "uses_json")
}

func find[T filesystem.Extractor](t *testing.T) T {
	t.Helper()
	exs, err := Extractors()
	require.NoError(t, err)
	for _, e := range exs {
		if v, ok := e.(T); ok {
			return v
		}
	}
	require.FailNow(t, "no extractor of the type")
	var zero T
	return zero
}

func fileAPI(t *testing.T, p string) filesystem.FileAPI {
	t.Helper()
	dir := t.TempDir()
	full := filepath.Join(dir, filepath.FromSlash(p))
	require.NoError(t, os.MkdirAll(filepath.Dir(full), 0o755))
	require.NoError(t, os.WriteFile(full, []byte("Name: x\nVersion: 1\n"), 0o644))
	info, err := os.Stat(full)
	require.NoError(t, err)
	return simplefileapi.New(p, info)
}
