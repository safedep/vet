package config

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPluginSchemas(t *testing.T) {
	schemas, err := pluginSchemas()
	require.NoError(t, err)
	for _, name := range []string{"dependency-cooldown", "lockfile", "malware", "vulnerability", "workflow", "table", "cloud", "tenant-policy", "cloud-inventory"} {
		b, ok := schemas[name]
		require.True(t, ok, "plugin %s has an options schema", name)
		var s map[string]any
		require.NoError(t, json.Unmarshal(b, &s), name)
		assert.Equal(t, "object", s["type"], name)
	}
}
