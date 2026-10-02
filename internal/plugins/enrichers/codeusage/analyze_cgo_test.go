//go:build cgo

package codeusage

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaultAnalyzer(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "app.py"), []byte("import requests\nfrom yaml import safe_load\n\nrequests.get(\"https://example.com\")\nsafe_load(\"a: 1\")\n"), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "node_modules", "x"), 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "node_modules", "x", "index.py"), []byte("import skipped\nskipped.run()\n"), 0o600))
	evs, err := defaultAnalyzer(context.Background(), dir)
	require.NoError(t, err)
	var modules []string
	for _, ev := range evs {
		modules = append(modules, ev.ModuleName)
	}
	assert.Contains(t, modules, "requests")
	assert.Contains(t, modules, "yaml")
	assert.NotContains(t, modules, "skipped", "installed code is not the project")
}
