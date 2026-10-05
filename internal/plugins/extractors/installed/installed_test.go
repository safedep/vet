package installed

import (
	"context"
	"os"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
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
	exs, err := Extractors()
	require.NoError(t, err)
	var gb filesystem.Extractor
	for _, e := range exs {
		if _, ok := e.(goBinary); ok {
			gb = e
		}
	}
	require.NotNil(t, gb)

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
