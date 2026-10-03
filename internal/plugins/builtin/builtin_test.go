package builtin

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/plugin"
)

func TestPluginsHaveUniqueSortedNames(t *testing.T) {
	names := Names()
	assert.True(t, slices.IsSorted(names))
	assert.Len(t, slices.Compact(slices.Clone(names)), len(names), "no two plugins share a name")
	for _, want := range []string{"dependency-cooldown", "lockfile", "codeusage", "cloud-inventory", "tenant-policy", "cyclonedx"} {
		assert.Contains(t, names, want)
	}
	for _, none := range []string{"insights", "malysis"} {
		assert.NotContains(t, names, none, "vet reads no plugins.%s section", none)
	}
}

func TestPluginsCheckTheDefaultOptionsAndGiveASchema(t *testing.T) {
	for _, p := range Plugins() {
		t.Run(p.Name, func(t *testing.T) {
			require.NoError(t, p.Check(plugin.MapConfig(nil)))
			_, err := p.Schema()
			require.NoError(t, err)
		})
	}
}
