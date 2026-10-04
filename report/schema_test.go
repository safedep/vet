package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSchemaIsCommitted fails when the Go types and the committed schemas
// differ. Run "UPDATE_SCHEMA=1 go test ./report/" to write the files.
func TestSchemaIsCommitted(t *testing.T) {
	for file, gen := range map[string]func() ([]byte, error){"report.schema.json": Schema, "report-line.schema.json": LineSchema} {
		t.Run(file, func(t *testing.T) {
			committed := filepath.Join("..", "schema", file)
			got, err := gen()
			require.NoError(t, err)
			got = append(got, '\n')

			if os.Getenv("UPDATE_SCHEMA") == "1" {
				require.NoError(t, os.MkdirAll(filepath.Dir(committed), 0o755))
				require.NoError(t, os.WriteFile(committed, got, 0o644))
			}

			want, err := os.ReadFile(committed)
			require.NoError(t, err, "run UPDATE_SCHEMA=1 go test ./report/ to write the schema")
			assert.Equal(t, string(want), string(got), "the report types changed: run UPDATE_SCHEMA=1 go test ./report/")
		})
	}
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
