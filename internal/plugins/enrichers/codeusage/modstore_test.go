package codeusage

import (
	"context"
	"errors"
	"testing"

	"github.com/safedep/code/fileindex"
	"github.com/safedep/code/fileindex/store"
	"github.com/safedep/code/fileindex/store/memstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingStore counts the artifact calls that reach the store, and fails
// them on demand.
type countingStore struct {
	store.Store
	gets, puts int
	fail       error
}

func (c *countingStore) GetArtifacts(ctx context.Context, keys []store.ArtifactKey) (map[store.ArtifactKey][]byte, error) {
	c.gets++
	if c.fail != nil {
		return nil, c.fail
	}
	return c.Store.GetArtifacts(ctx, keys)
}

func (c *countingStore) PutArtifacts(ctx context.Context, artifacts []store.Artifact) error {
	c.puts++
	if c.fail != nil {
		return c.fail
	}
	return c.Store.PutArtifacts(ctx, artifacts)
}

func packageKey(unit, dir string) store.ArtifactKey {
	return store.ArtifactKey{Key: fileindex.Key{Path: fileindex.UnitPath(unit, dir), ContentHash: "h1:x"}, Plugin: "modgraph", Version: "2"}
}

func TestModuleStoreKeepsOneArtifactForEachModule(t *testing.T) {
	ctx := context.Background()
	under := &countingStore{Store: memstore.New()}
	unit := "go:example.com/a@v1.0.0"
	s := newModuleStore(under)
	require.NoError(t, s.PutArtifacts(ctx, []store.Artifact{
		{Key: packageKey(unit, "."), Data: []byte(`{"imports":[]}`)},
		{Key: packageKey(unit, "x"), Data: []byte(`{"imports":[{"path":"fmt"}]}`)},
	}))
	assert.Equal(t, 0, under.puts, "a put waits for Flush")
	s.Flush(ctx)
	assert.Equal(t, 1, under.puts, "Flush writes the module in one call")
	s.Flush(ctx)
	assert.Equal(t, 1, under.puts, "a module that no put changed is not written again")

	next := newModuleStore(under)
	under.gets = 0
	found, err := next.GetArtifacts(ctx, []store.ArtifactKey{packageKey(unit, "x")})
	require.NoError(t, err)
	assert.JSONEq(t, `{"imports":[{"path":"fmt"}]}`, string(found[packageKey(unit, "x")]))
	found, err = next.GetArtifacts(ctx, []store.ArtifactKey{packageKey(unit, "."), packageKey(unit, "missing")})
	require.NoError(t, err)
	assert.Len(t, found, 1)
	assert.Equal(t, 1, under.gets, "a scan reads each module once")
}

func TestModuleStorePassesOnAKeyWithNoUnit(t *testing.T) {
	ctx := context.Background()
	under := &countingStore{Store: memstore.New()}
	s := newModuleStore(under)
	k := store.ArtifactKey{Key: fileindex.Key{Path: "main.go"}, Plugin: "modgraph"}
	require.NoError(t, s.PutArtifacts(ctx, []store.Artifact{{Key: k, Data: []byte("x")}}))
	assert.Equal(t, 1, under.puts)
	found, err := s.GetArtifacts(ctx, []store.ArtifactKey{k})
	require.NoError(t, err)
	assert.Equal(t, []byte("x"), found[k])
}

func TestModuleStoreTreatsAFailedOrBadEntryAsAMiss(t *testing.T) {
	ctx := context.Background()
	unit := "go:example.com/a@v1.0.0"
	mk, _, ok := moduleKey(packageKey(unit, "."))
	require.True(t, ok)

	bad := memstore.New()
	require.NoError(t, bad.PutArtifacts(ctx, []store.Artifact{{Key: mk, Data: []byte("not json")}}))
	found, err := newModuleStore(bad).GetArtifacts(ctx, []store.ArtifactKey{packageKey(unit, ".")})
	require.NoError(t, err)
	assert.Empty(t, found)

	failing := &countingStore{Store: memstore.New(), fail: errors.New("disk full")}
	s := newModuleStore(failing)
	found, err = s.GetArtifacts(ctx, []store.ArtifactKey{packageKey(unit, ".")})
	require.NoError(t, err, "a cache that fails costs time, not the graph")
	assert.Empty(t, found)
	found, err = s.GetArtifacts(ctx, []store.ArtifactKey{packageKey("go:example.com/b@v1.0.0", ".")})
	require.NoError(t, err)
	assert.Empty(t, found)
	assert.Equal(t, 1, failing.gets, "the module store stops at the first error")
	require.NoError(t, s.PutArtifacts(ctx, []store.Artifact{{Key: packageKey(unit, "."), Data: []byte(`{"imports":[]}`)}}))
	s.Flush(ctx)
	assert.Equal(t, 0, failing.puts)
}
