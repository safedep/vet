package inventory_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/cloud/inventory"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

func TestStub(t *testing.T) {
	cases := []struct {
		name string
		opts map[string]any
		err  bool
	}{
		{name: "no options"},
		{name: "an endpoint id", opts: map[string]any{"endpoint_id": "gh:safedep/vet"}},
		{name: "unknown option", opts: map[string]any{"wal": "x"}, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := inventory.New(plugin.MapConfig(tc.opts))
			if tc.err {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			items := []report.InventoryItem{{Kind: report.InventoryMCPServer, Name: "fs"}}
			assert.ErrorIs(t, s.Sync(context.Background(), items), plugin.ErrUnavailable)
			var schema map[string]any
			require.NoError(t, json.Unmarshal(s.OptionsSchema(), &schema))
			assert.Contains(t, schema["properties"], "endpoint_id")
		})
	}
}
