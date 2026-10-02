package table

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func TestLimit(t *testing.T) {
	output.SetWidthOverride(120)
	t.Cleanup(func() { output.SetWidthOverride(0) })
	cases := []struct {
		name    string
		options plugin.MapConfig
		more    bool
	}{
		{name: "limit 1", options: plugin.MapConfig{"limit": 1}, more: true},
		{name: "all", options: plugin.MapConfig{"all": true, "limit": 1}},
		{name: "default", options: plugin.MapConfig(nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(tc.options)
			require.NoError(t, err)
			got := string(plugintest.TestSink(t, s, plugintest.SampleReport()))
			if tc.more {
				assert.Contains(t, got, "1 more (vet report show -o table --all)")
				assert.NotContains(t, got, "unpinned-action")
				return
			}
			assert.NotContains(t, got, "more (")
			assert.Contains(t, got, "unpinned-action")
		})
	}
	_, err := New(plugin.MapConfig{"limit": -1})
	assert.Error(t, err)
}
