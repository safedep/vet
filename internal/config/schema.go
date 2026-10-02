package config

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/invopop/jsonschema"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

// SchemaURL is the id of the config schema.
const SchemaURL = "https://schemas.safedep.io/vet/config/v2.json"

// Schema returns the JSON Schema of the config file. plugins maps a plugin
// name to the JSON Schema of its options. Another plugin name stays open,
// because a third-party plugin can register at run time.
func Schema(plugins map[string][]byte) ([]byte, error) {
	r := &jsonschema.Reflector{FieldNameTag: "yaml", AllowAdditionalProperties: false, DoNotReference: true, RequiredFromJSONSchemaTags: true}
	s := r.Reflect(&Config{})
	s.ID = SchemaURL
	s.Title = "vet config"
	s.Description = "The vet config file, config.yml. vet config schema get prints it."

	section := func(options *jsonschema.Schema) *jsonschema.Schema {
		props := orderedmap.New[string, *jsonschema.Schema]()
		props.Set("enabled", &jsonschema.Schema{Type: "boolean"})
		props.Set("options", options)
		return &jsonschema.Schema{Type: "object", Properties: props, AdditionalProperties: jsonschema.FalseSchema}
	}
	known := orderedmap.New[string, *jsonschema.Schema]()
	names := make([]string, 0, len(plugins))
	for n := range plugins {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		var opts jsonschema.Schema
		if err := json.Unmarshal(plugins[n], &opts); err != nil {
			return nil, fmt.Errorf("options schema of plugin %s: %w", n, err)
		}
		known.Set(n, section(&opts))
	}
	pluginsSchema := &jsonschema.Schema{
		Type:                 "object",
		Description:          "The section of each plugin: plugins.<name>.enabled and plugins.<name>.options.",
		Properties:           known,
		AdditionalProperties: section(&jsonschema.Schema{Type: "object"}),
	}
	if s.Properties == nil {
		return nil, fmt.Errorf("config schema has no properties")
	}
	s.Properties.Set("plugins", pluginsSchema)
	return json.MarshalIndent(s, "", "  ")
}
