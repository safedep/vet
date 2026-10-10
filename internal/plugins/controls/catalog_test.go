package controls

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCatalogIDsAreUnique(t *testing.T) {
	list, err := Catalog()
	require.NoError(t, err)
	seen := map[string]bool{}
	for _, c := range list {
		assert.False(t, seen[c.ID], "control id %s is unique", c.ID)
		assert.NotEmpty(t, c.Plugin, c.ID)
		seen[c.ID] = true
	}
}

func TestAttackIDs(t *testing.T) {
	ids, err := AttackIDs()
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"malware", "impostor-commit", "suspicious-command", "padded-code", "disguised-script", "unicode-payload", "history-rewrite-script"}, ids)
}
