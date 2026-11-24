package config

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSchemaValidatesConfigFiles(t *testing.T) {
	b, err := Schema(testPlugins, map[string][]byte{
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
		{name: "a plugin with no options schema", json: `{"plugins":{"table":{"options":{"top":5}}}}`, ok: true},
		{name: "a plugin that is off by default", json: `{"plugins":{"tenant-policy":{"enabled":true}}}`, ok: true},
		{name: "another plugin", json: `{"plugins":{"my-plugin":{"options":{"x":1}}}}`},
		{name: "enabled on a report format", json: `{"plugins":{"table":{"enabled":false}}}`},
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

func TestSchemaDescribesEachPlugin(t *testing.T) {
	ps := []Plugin{
		{Name: "vulnerability", Description: "Reports known vulnerabilities.", Switch: true, On: true},
		{Name: "tenant-policy", Description: "Adds the tenant policy.", Switch: true},
		{Name: "json", Description: "Report format."},
	}
	b, err := Schema(ps, nil)
	require.NoError(t, err)
	var doc struct {
		Properties struct {
			Plugins struct {
				Properties map[string]struct {
					Description string `json:"description"`
					Properties  map[string]struct {
						Default     *bool  `json:"default"`
						Description string `json:"description"`
					} `json:"properties"`
				} `json:"properties"`
			} `json:"plugins"`
		} `json:"properties"`
	}
	require.NoError(t, json.Unmarshal(b, &doc))
	got := doc.Properties.Plugins.Properties
	require.Len(t, got, 3)
	assert.Equal(t, "Reports known vulnerabilities.", got["vulnerability"].Description)
	assert.Equal(t, "Turn the plugin on or off. The default is on.", got["vulnerability"].Properties["enabled"].Description)
	require.NotNil(t, got["tenant-policy"].Properties["enabled"].Default)
	assert.False(t, *got["tenant-policy"].Properties["enabled"].Default)
	assert.Equal(t, "Turn the plugin on or off. The default is off.", got["tenant-policy"].Properties["enabled"].Description)
	assert.NotContains(t, got["json"].Properties, "enabled", "-o and --report select a report format")
	assert.Contains(t, got["json"].Properties, "options")
}
