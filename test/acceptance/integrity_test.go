package acceptance

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCatalogIntegrity runs under go test ./... It fails when a script has
// no catalog row, so a typo cannot become a guarantee. A row with no
// script is a gap. The report shows it, and it does not fail the build.
func TestCatalogIntegrity(t *testing.T) {
	cat, err := LoadCatalog("catalog.yaml")
	require.NoError(t, err)

	scriptIDs, err := DiscoverScripts("scripts")
	require.NoError(t, err)

	for _, id := range scriptIDs {
		assert.Truef(t, cat.Has(id), "script %q.txtar has no catalog.yaml row. Add one", id)
		assert.GreaterOrEqualf(t, strings.Count(id, "/"), 2, "script %q.txtar must be at least two levels deep", id)
	}
	for _, g := range cat.Guarantees() {
		assert.NotEmptyf(t, g.Title, "catalog row %s has no title", g.ID)
		assert.NotEmptyf(t, g.Guarantee, "catalog row %s has no guarantee", g.ID)
	}
}
