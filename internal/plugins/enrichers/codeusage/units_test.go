package codeusage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
)

func mkfile(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
}

func TestUnitOf(t *testing.T) {
	dir, cache, cargo := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("GOMODCACHE", cache)
	t.Setenv("CARGO_HOME", cargo)
	mkfile(t, filepath.Join(dir, "vendor", "modules.txt"), "# example.com/vendored v1.2.0\n# example.com/stale v1.0.0\n")
	mkfile(t, filepath.Join(dir, "vendor", "example.com", "vendored", "a.go"), "package a\n")
	mkfile(t, filepath.Join(dir, "vendor", "example.com", "stale", "a.go"), "package a\n")
	mkfile(t, filepath.Join(cache, "github.com", "!azure", "sdk@v0.3.0", "a.go"), "package a\n")
	mkfile(t, filepath.Join(dir, "vendor", "serde", "Cargo.toml"), "[package]\nname = \"serde\"\nversion = \"1.0.200\"\n")
	mkfile(t, filepath.Join(dir, "vendor", "old", "Cargo.toml"), "[package]\nname = \"old\"\nversion = \"0.1.0\"\n")
	mkfile(t, filepath.Join(cargo, "registry", "src", "index.crates.io-6f17d22bba15001f", "time-0.3.30", "Cargo.toml"), "[package]\n")
	mkfile(t, filepath.Join(dir, "secret-1.0.0", "Cargo.toml"), "[package]\n")

	cases := []struct {
		name string
		id   model.PackageVersion
		dir  string
	}{
		{"a vendored module", model.MustPackageVersion(model.EcosystemGo, "example.com/vendored", "1.2.0"), filepath.Join(dir, "vendor", "example.com", "vendored")},
		{"a vendor tree of another version", model.MustPackageVersion(model.EcosystemGo, "example.com/stale", "v1.1.0"), ""},
		{"a module in the cache, with its escaped path", model.MustPackageVersion(model.EcosystemGo, "github.com/Azure/sdk", "v0.3.0"), filepath.Join(cache, "github.com", "!azure", "sdk@v0.3.0")},
		{"the standard library", model.MustPackageVersion(model.EcosystemGo, "stdlib", "1.27.1"), ""},
		{"a vendored crate", model.MustPackageVersion(model.EcosystemCargo, "serde", "1.0.200"), filepath.Join(dir, "vendor", "serde")},
		{"a vendored crate of another version", model.MustPackageVersion(model.EcosystemCargo, "old", "0.2.0"), ""},
		{"a crate in the registry", model.MustPackageVersion(model.EcosystemCargo, "time", "0.3.30"), filepath.Join(cargo, "registry", "src", "index.crates.io-6f17d22bba15001f", "time-0.3.30")},
		{"a crate name that leaves the vendor directory", model.MustPackageVersion(model.EcosystemCargo, "../secret", "1.0.0"), ""},
		{"a crate name with a pattern", model.MustPackageVersion(model.EcosystemCargo, "ti*", "0.3.30"), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			u, ok := unitOf(dir, c.id)
			assert.Equal(t, c.dir != "", ok)
			assert.Equal(t, c.dir, u.Dir)
		})
	}
}
