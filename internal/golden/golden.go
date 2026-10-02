// Package golden compares test output with a committed golden file.
// UPDATE_GOLDEN=1 rewrites the files.
package golden

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// UpdateEnv rewrites the golden files when it is "1".
const UpdateEnv = "UPDATE_GOLDEN"

// Assert compares got with the file at path.
func Assert(t *testing.T, path string, got []byte) {
	t.Helper()
	if os.Getenv(UpdateEnv) == "1" {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, got, 0o644))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err, "missing golden file: run with %s=1", UpdateEnv)
	assert.Equal(t, string(want), string(got), "golden file %s differs: run with %s=1 to update", path, UpdateEnv)
}

// AssertJSON compares v, encoded as indented JSON, with the file at path.
func AssertJSON(t *testing.T, path string, v any) {
	t.Helper()
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	require.NoError(t, enc.Encode(v))
	Assert(t, path, b.Bytes())
}
