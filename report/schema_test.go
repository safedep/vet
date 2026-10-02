package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// committedSchema is the schema file that the repository keeps.
var committedSchema = filepath.Join("..", "schema", "report.schema.json")

// TestSchemaIsCommitted fails when the Go types and the committed schema
// differ. Run "UPDATE_SCHEMA=1 go test ./report/" to write the file.
func TestSchemaIsCommitted(t *testing.T) {
	got, err := Schema()
	require.NoError(t, err)
	got = append(got, '\n')

	if os.Getenv("UPDATE_SCHEMA") == "1" {
		require.NoError(t, os.MkdirAll(filepath.Dir(committedSchema), 0o755))
		require.NoError(t, os.WriteFile(committedSchema, got, 0o644))
	}

	want, err := os.ReadFile(committedSchema)
	require.NoError(t, err, "run UPDATE_SCHEMA=1 go test ./report/ to write the schema")
	assert.Equal(t, string(want), string(got), "the report types changed: run UPDATE_SCHEMA=1 go test ./report/")
}

func TestSchemaListsEnums(t *testing.T) {
	b, err := Schema()
	require.NoError(t, err)

	var s map[string]any
	require.NoError(t, json.Unmarshal(b, &s))
	assert.Equal(t, SchemaURL, s["$id"])

	defs, ok := s["$defs"].(map[string]any)
	require.True(t, ok)
	finding, ok := defs["Finding"].(map[string]any)
	require.True(t, ok)
	props := finding["properties"].(map[string]any)
	sev := props["severity"].(map[string]any)
	assert.Equal(t, []any{"critical", "high", "medium", "low", "info"}, sev["enum"])
}
