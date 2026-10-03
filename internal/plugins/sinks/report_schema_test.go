package sinks_test

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/sinks"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

// TestReportMatchesSchema checks "-o json" against report.schema.json and
// each line of "-o jsonl" against report-line.schema.json.
func TestReportMatchesSchema(t *testing.T) {
	compile := func(file, id string) *jsonschema.Schema {
		data, err := os.ReadFile(filepath.Join("..", "..", "..", "schema", file))
		require.NoError(t, err)
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		require.NoError(t, err)
		c := jsonschema.NewCompiler()
		require.NoError(t, c.AddResource(id, doc))
		s, err := c.Compile(id)
		require.NoError(t, err)
		return s
	}
	document := compile("report.schema.json", report.SchemaURL)
	line := compile("report-line.schema.json", report.LineSchemaURL)

	for name, build := range map[string]func() *plugintest.MemState{"sample": plugintest.SampleReport, "pull-request": pullRequest} {
		t.Run(name+"/json", func(t *testing.T) {
			s, err := sinks.Builtin().New("json", nil)
			require.NoError(t, err)
			inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(plugintest.TestSink(t, s, build())))
			require.NoError(t, err)
			require.NoError(t, document.Validate(inst))
		})
		t.Run(name+"/jsonl", func(t *testing.T) {
			s, err := sinks.Builtin().New("jsonl", nil)
			require.NoError(t, err)
			sc := bufio.NewScanner(bytes.NewReader(plugintest.TestSink(t, s, build())))
			sc.Buffer(nil, 1<<20)
			n := 0
			for sc.Scan() {
				inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(sc.Bytes()))
				require.NoError(t, err)
				require.NoError(t, line.Validate(inst), "line %d", n+1)
				n++
			}
			require.NoError(t, sc.Err())
			require.Greater(t, n, 2, "a header, records and a trailer")
		})
	}
}
