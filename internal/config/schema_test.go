package config

import (
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchemaValidatesConfigFiles(t *testing.T) {
	b, err := Schema(map[string][]byte{
		"dependency-cooldown": []byte(`{"type":"object","properties":{"days":{"type":"integer"}},"additionalProperties":false}`),
	})
	require.NoError(t, err)
	doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(b)))
	require.NoError(t, err)
	c := jsonschema.NewCompiler()
	require.NoError(t, c.AddResource(SchemaURL, doc))
	sch, err := c.Compile(SchemaURL)
	require.NoError(t, err)

	cases := []struct {
		name string
		json string
		ok   bool
	}{
		{name: "empty", json: `{}`, ok: true},
		{name: "known keys", json: `{"scan":{"concurrency":4,"exclude":["vendor"]},"policy":{"fail_on":"high"}}`, ok: true},
		{name: "plugin options", json: `{"plugins":{"dependency-cooldown":{"enabled":true,"options":{"days":7}}}}`, ok: true},
		{name: "another plugin", json: `{"plugins":{"my-plugin":{"options":{"x":1}}}}`, ok: true},
		{name: "unknown key", json: `{"scan":{"concurency":4}}`},
		{name: "unknown plugin option", json: `{"plugins":{"dependency-cooldown":{"options":{"weeks":1}}}}`},
		{name: "wrong type", json: `{"scan":{"concurrency":"many"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inst, err := jsonschema.UnmarshalJSON(strings.NewReader(tc.json))
			require.NoError(t, err)
			err = sch.Validate(inst)
			if tc.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
