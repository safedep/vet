package acceptance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDeriveFeatureID(t *testing.T) {
	cases := map[string]string{
		"npm/guard/malware-block.txtar":     "npm/guard/malware-block",
		"npm/dry-run/clean-allow.txtar":     "npm/dry-run/clean-allow",
		"setup/install/shims-created.txtar": "setup/install/shims-created",
	}
	for in, want := range cases {
		assert.Equal(t, want, DeriveFeatureID(filepath.FromSlash(in)))
	}
}

func TestLoadCatalog(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
- id: npm/guard/malware-block
  title: "npm install of a known-malicious package is blocked"
  category: npm
  tier: P0
  guarantee: "A malware verdict is never installed; vet exits non-zero."
- id: setup/install/shims-created
  title: "setup install creates shims"
  category: setup
  tier: P1
  guarantee: "vet creates the shims."
  labels: [shims, offline]
`), 0o600))

	cat, err := LoadCatalog(path)
	require.NoError(t, err)
	assert.Equal(t, []string{"npm/guard/malware-block", "setup/install/shims-created"}, cat.IDs())
	assert.True(t, cat.Has("npm/guard/malware-block"))
	g, ok := cat.Get("setup/install/shims-created")
	require.True(t, ok)
	assert.Equal(t, TierP1, g.Tier)
	assert.Equal(t, "setup", g.Category)
	assert.Equal(t, []string{"shims", "offline"}, g.Labels)
}

func TestCatalogSelects(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
- id: npm/guard/malware-block
  category: npm
  tier: P0
  guarantee: x
  labels: [malware, npm]
- id: npm/install/clean-allow
  category: npm
  tier: P1
  guarantee: y
  labels: [clean, npm]
- id: setup/install/shims-created
  category: setup
  tier: P1
  guarantee: z
  labels: [shims, offline]
`), 0o600))
	cat, err := LoadCatalog(path)
	require.NoError(t, err)

	// Empty selector matches everything, including an un-cataloged id.
	assert.True(t, cat.Selects("npm/guard/malware-block", Selector{}))
	assert.True(t, cat.Selects("not/in/catalog", Selector{}))

	// Category filter.
	assert.True(t, cat.Selects("npm/guard/malware-block", Selector{Category: "npm"}))
	assert.False(t, cat.Selects("setup/install/shims-created", Selector{Category: "npm"}))

	// Label filter matches when any label overlaps.
	assert.True(t, cat.Selects("npm/guard/malware-block", Selector{Labels: []string{"malware"}}))
	assert.False(t, cat.Selects("npm/install/clean-allow", Selector{Labels: []string{"malware"}}))

	// Category and labels combine (AND across fields, OR within labels).
	assert.True(t, cat.Selects("npm/install/clean-allow", Selector{Category: "npm", Labels: []string{"clean", "malware"}}))
	assert.False(t, cat.Selects("setup/install/shims-created", Selector{Category: "setup", Labels: []string{"malware"}}))

	// A filtered run never includes an un-cataloged id.
	assert.False(t, cat.Selects("not/in/catalog", Selector{Category: "npm"}))
}

func TestLoadCatalogRejectsBadTierAndDupes(t *testing.T) {
	dir := t.TempDir()
	badTier := filepath.Join(dir, "bad.yaml")
	require.NoError(t, os.WriteFile(badTier, []byte(`
- id: a/b/c
  category: a
  tier: P9
  guarantee: x
`), 0o600))
	_, err := LoadCatalog(badTier)
	assert.Error(t, err)

	dupe := filepath.Join(dir, "dupe.yaml")
	require.NoError(t, os.WriteFile(dupe, []byte(`
- id: a/b/c
  category: a
  tier: P0
  guarantee: x
- id: a/b/c
  category: a
  tier: P0
  guarantee: y
`), 0o600))
	_, err = LoadCatalog(dupe)
	assert.Error(t, err)
}

func TestLoadCatalogRejectsCategoryMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "mismatch.yaml")
	require.NoError(t, os.WriteFile(path, []byte(`
- id: npm/guard/malware-block
  category: npn
  tier: P0
  guarantee: x
`), 0o600))
	_, err := LoadCatalog(path)
	assert.ErrorContains(t, err, "must match id head")
}
