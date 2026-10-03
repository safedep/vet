package sinks_test

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/sinks"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

// TestCycloneDXMatchesSchema checks the cyclonedx report against the
// CycloneDX 1.7 JSON schema. testdata/cyclonedx-1.7 holds the schema files
// of github.com/CycloneDX/specification.
func TestCycloneDXMatchesSchema(t *testing.T) {
	c := jsonschema.NewCompiler()
	for _, f := range []string{"bom-1.7", "spdx", "jsf-0.82", "cryptography-defs"} {
		data, err := os.ReadFile(filepath.Join("testdata", "cyclonedx-1.7", f+".schema.json"))
		require.NoError(t, err)
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
		require.NoError(t, err)
		require.NoError(t, c.AddResource("http://cyclonedx.org/schema/"+f+".schema.json", doc))
	}
	schema, err := c.Compile("http://cyclonedx.org/schema/bom-1.7.schema.json")
	require.NoError(t, err)

	reports := map[string]func() *plugintest.MemState{
		"empty":        func() *plugintest.MemState { return &plugintest.MemState{} },
		"sample":       plugintest.SampleReport,
		"pull-request": pullRequest,
		"clean":        clean,
	}
	for name, build := range reports {
		t.Run(name, func(t *testing.T) {
			s, err := sinks.Builtin().New("cyclonedx", nil)
			require.NoError(t, err)
			bom, err := jsonschema.UnmarshalJSON(bytes.NewReader(plugintest.TestSink(t, s, build())))
			require.NoError(t, err)
			require.NoError(t, schema.Validate(bom))
		})
	}
}
