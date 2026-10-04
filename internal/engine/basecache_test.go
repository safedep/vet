package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-git/go-git/v5/plumbing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
)

func TestBaseCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	c := baseCache{dir: dir, target: "t", path: filepath.Join(dir, "t-1.json")}
	m := &model.Manifest{ID: "m1", Path: "package-lock.json", Ecosystem: model.EcosystemNpm, Kind: model.ManifestKindLockfile, Extractor: "javascript/packagelockjson"}
	m.Packages = []*model.Package{
		{ID: model.MustPackageVersion(model.EcosystemNpm, "left-pad", "1.2.0"), Direct: true, Integrity: "sha512-a", Resolved: "https://registry.npmjs.org/left-pad/-/left-pad-1.2.0.tgz"},
		{ID: model.MustPackageVersion(model.EcosystemNpm, "ms", "2.1.3"), Dev: true},
	}
	want := &base{
		manifests: map[string]*model.Manifest{"m1": m},
		hashes:    map[string]plumbing.Hash{"package-lock.json": plumbing.ComputeHash(plumbing.BlobObject, []byte("x"))},
	}
	require.NoError(t, c.save(want))

	got, ok := c.load()
	require.True(t, ok)
	assert.Equal(t, want, got)

	info, err := os.Stat(c.path)
	require.NoError(t, err)
	if os.PathSeparator == '/' {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestBaseCacheMissing(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{"), 0o600))
	for _, name := range []string{"absent.json", "bad.json"} {
		_, ok := baseCache{dir: dir, target: "t", path: filepath.Join(dir, name)}.load()
		assert.False(t, ok, name)
	}
}

func TestBaseCachePrune(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "u-1.json")
	require.NoError(t, os.WriteFile(other, []byte("{}"), 0o600))
	for i := range keepBases + 2 {
		c := baseCache{dir: dir, target: "t", path: filepath.Join(dir, fmt.Sprintf("t-%d.json", i))}
		require.NoError(t, c.save(&base{}))
	}
	kept, err := filepath.Glob(filepath.Join(dir, "t-*.json"))
	require.NoError(t, err)
	assert.Len(t, kept, keepBases)
	assert.FileExists(t, other, "vet keeps the bases of other targets")
}
