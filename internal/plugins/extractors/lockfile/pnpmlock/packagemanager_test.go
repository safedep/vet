package pnpmlock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/lockmeta"
)

func envLockfile() pnpmLockfile {
	return pnpmLockfile{
		Version: 9.0,
		Importers: map[string]pnpmImporter{".": {
			PackageManagerDependencies: map[string]pnpmImporterDep{"pnpm": {Version: "10.11.0"}},
		}},
		Snapshots: map[string]pnpmSnapshot{
			"pnpm@10.11.0": {OptionalDependencies: map[string]string{"@pnpm/exe.linux-x64": "10.11.0"}},
		},
	}
}

func envPackages() ([]*extractor.Package, []string) {
	keys := []string{"pnpm@10.11.0", "@pnpm/exe.linux-x64@10.11.0", "other@1.0.0"}
	var pkgs []*extractor.Package
	for range keys {
		pkgs = append(pkgs, &extractor.Package{Metadata: &lockmeta.Metadata{}})
	}
	return pkgs, keys
}

func declared(pkgs []*extractor.Package) []bool {
	var out []bool
	for _, p := range pkgs {
		out = append(out, p.Metadata.(*lockmeta.Metadata).DeclaredAt != nil)
	}
	return out
}

func TestDeclarePackageManager(t *testing.T) {
	const pj = "{\n  \"name\": \"app\",\n  \"packageManager\": \"pnpm@10.11.0+sha512.00\"\n}\n"
	cases := []struct {
		name  string
		setup func(t *testing.T, dir string)
		lf    func() pnpmLockfile
		want  []bool
	}{
		{name: "the field names pnpm", setup: func(t *testing.T, dir string) { write(t, dir, pj) }, want: []bool{true, true, false}},
		{name: "no package.json", setup: func(*testing.T, string) {}, want: []bool{false, false, false}},
		{name: "the field names another tool", setup: func(t *testing.T, dir string) { write(t, dir, strings.Replace(pj, "pnpm@", "yarn@", 1)) }, want: []bool{false, false, false}},
		{name: "a link", setup: func(t *testing.T, dir string) {
			write(t, dir, pj)
			require.NoError(t, os.Rename(filepath.Join(dir, "package.json"), filepath.Join(dir, "real.json")))
			require.NoError(t, os.Symlink("real.json", filepath.Join(dir, "package.json")))
		}, want: []bool{false, false, false}},
		{name: "a file over the size limit", setup: func(t *testing.T, dir string) {
			write(t, dir, strings.Replace(pj, `"app"`, `"`+strings.Repeat("a", maxPackageJSON)+`"`, 1))
		}, want: []bool{false, false, false}},
		{name: "a document that also installs the project", setup: func(t *testing.T, dir string) { write(t, dir, pj) }, lf: func() pnpmLockfile {
			lf := envLockfile()
			imp := lf.Importers["."]
			imp.Dependencies = map[string]pnpmImporterDep{"other": {Version: "1.0.0"}}
			lf.Importers["."] = imp
			return lf
		}, want: []bool{false, false, false}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			tc.setup(t, dir)
			lf := envLockfile()
			if tc.lf != nil {
				lf = tc.lf()
			}
			pkgs, keys := envPackages()
			require.NoError(t, declarePackageManager(os.DirFS(dir), "pnpm-lock.yaml", lf, pkgs, keys))
			assert.Equal(t, tc.want, declared(pkgs))
		})
	}
}

func write(t *testing.T, dir, data string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package.json"), []byte(data), 0o600))
}
