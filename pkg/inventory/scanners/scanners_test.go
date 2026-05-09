package scanners

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildEmptyKindsReturnsAll(t *testing.T) {
	got, err := Build(nil)
	require.NoError(t, err)
	assert.Len(t, got, len(registry))
}

func TestBuildSingleKindReturnsOnlyThatKind(t *testing.T) {
	require.NotEmpty(t, registry, "registry must declare at least one scanner")
	first := registry[0].Kind
	got, err := Build([]string{first})
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

func TestBuildUnknownKindRejected(t *testing.T) {
	_, err := Build([]string{"not-a-real-kind"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-a-real-kind")
}

func TestBuildRejectsUnknownAmongValid(t *testing.T) {
	require.NotEmpty(t, registry)
	_, err := Build([]string{registry[0].Kind, "bogus"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus")
}

func TestAllowedKindsMatchesRegistry(t *testing.T) {
	got := AllowedKinds()
	require.Len(t, got, len(registry))
	for i, d := range registry {
		assert.Equal(t, d.Kind, got[i])
	}
}

func TestAllowedKindsReturnsIndependentSlice(t *testing.T) {
	a := AllowedKinds()
	if len(a) == 0 {
		t.Skip("registry is empty")
	}
	a[0] = "mutated"
	assert.NotEqual(t, "mutated", AllowedKinds()[0],
		"AllowedKinds must not expose the internal slice")
}

func TestRegistryEntriesAreUniqueByKind(t *testing.T) {
	seen := make(map[string]struct{}, len(registry))
	for _, d := range registry {
		_, dup := seen[d.Kind]
		assert.Falsef(t, dup, "duplicate kind in registry: %q", d.Kind)
		seen[d.Kind] = struct{}{}
		assert.NotNil(t, d.New, "descriptor %q has nil New", d.Kind)
	}
}
