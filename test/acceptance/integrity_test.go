package acceptance

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalogIntegrity(t *testing.T) {
	cat, err := LoadCatalog("catalog.yaml")
	require.NoError(t, err)

	scriptIDs, err := DiscoverScripts("scripts")
	require.NoError(t, err)

	for _, id := range scriptIDs {
		assert.Truef(t, cat.Has(id),
			"script %q.txtar has no catalog.yaml entry; add one so it cannot become a phantom guarantee", id)
	}
	// Catalog ids without a script are soft gaps: reported, not failed.
}
