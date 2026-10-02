package inventory_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/cloud/inventory"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

var items = []report.InventoryItem{{Kind: report.InventoryMCPServer, Name: "fs"}}

func TestStub(t *testing.T) {
	cases := []struct {
		name     string
		opts     map[string]any
		endpoint string
		err      bool
	}{
		{name: "no options", endpoint: "endpoint:host"},
		{name: "an endpoint id", opts: map[string]any{"endpoint_id": "gh:safedep/vet"}, endpoint: "gh:safedep/vet"},
		{name: "unknown option", opts: map[string]any{"wal": "x"}, err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wal := inventory.NewWAL(t.TempDir())
			s, err := inventory.New(plugin.MapConfig(tc.opts), wal)
			if tc.err {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.ErrorIs(t, s.Sync(context.Background(), "endpoint:host", items), plugin.ErrUnavailable)

			batches, err := wal.Batches()
			require.NoError(t, err)
			require.Len(t, batches, 1, "the batch waits in the log")
			assert.Equal(t, tc.endpoint, batches[0].Endpoint)
			assert.Equal(t, items, batches[0].Items)

			var schema map[string]any
			require.NoError(t, json.Unmarshal(s.OptionsSchema(), &schema))
			assert.Contains(t, schema["properties"], "endpoint_id")
		})
	}
}

func TestWAL(t *testing.T) {
	wal := inventory.NewWAL(t.TempDir())
	batches, err := wal.Batches()
	require.NoError(t, err)
	assert.Empty(t, batches, "a missing log has no batch")

	for i := range 55 {
		require.NoError(t, wal.Append(inventory.Batch{At: time.Unix(int64(i), 0).UTC(), Endpoint: fmt.Sprint(i), Items: items}))
	}
	batches, err = wal.Batches()
	require.NoError(t, err)
	require.Len(t, batches, 50, "the log keeps the last 50 batches")
	assert.Equal(t, "5", batches[0].Endpoint)
	assert.Equal(t, "54", batches[49].Endpoint)

	if runtime.GOOS != "windows" {
		info, err := os.Stat(wal.Path())
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}

	require.NoError(t, wal.Clear())
	require.NoError(t, wal.Clear(), "a second clear does nothing")
	batches, err = wal.Batches()
	require.NoError(t, err)
	assert.Empty(t, batches)

	require.NoError(t, os.WriteFile(wal.Path(), []byte("{bad\n"), 0o600))
	_, err = wal.Batches()
	assert.ErrorContains(t, err, "inventory log")
}
