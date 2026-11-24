package config

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/invopop/jsonschema"
	orderedmap "github.com/wk8/go-ordered-map/v2"
)

// SchemaURL is the id of the config schema.
const SchemaURL = "https://schemas.safedep.io/vet/config/v2.json"

// Schema returns the JSON Schema of the config file. It lists each built-in
// plugin with its description. options maps a plugin name to the JSON Schema
// of its options. The schema has an enabled key only for a plugin with a
// switch, and no other plugin name.
func Schema(plugins []Plugin, options map[string][]byte) ([]byte, error) {
	r := &jsonschema.Reflector{FieldNameTag: "yaml", AllowAdditionalProperties: false, DoNotReference: true, RequiredFromJSONSchemaTags: true}
	s := r.Reflect(&Config{})
	s.ID = SchemaURL
	s.Title = "vet config"
	s.Description = "The vet config file, config.yml. vet config schema get prints it."

	sorted := slices.Clone(plugins)
	slices.SortFunc(sorted, func(a, b Plugin) int { return strings.Compare(a.Name, b.Name) })
	known := orderedmap.New[string, *jsonschema.Schema]()
	for _, p := range sorted {
		opts := &jsonschema.Schema{Type: "object"}
		if raw, ok := options[p.Name]; ok {
			if err := json.Unmarshal(raw, opts); err != nil {
				return nil, fmt.Errorf("options schema of plugin %s: %w", p.Name, err)
			}
		}
		props := orderedmap.New[string, *jsonschema.Schema]()
		if p.Switch {
			props.Set("enabled", &jsonschema.Schema{
				Type:        "boolean",
				Default:     p.On,
				Description: fmt.Sprintf("Turn the plugin on or off. The default is %s.", onOff(p.On)),
			})
		}
		props.Set("options", opts)
		known.Set(p.Name, &jsonschema.Schema{
			Type: "object", Description: p.Description, Properties: props, AdditionalProperties: jsonschema.FalseSchema,
		})
	}
	pluginsSchema := &jsonschema.Schema{
		Type:                 "object",
		Description:          "The section of each built-in plugin: plugins.<name>.enabled and plugins.<name>.options. A report format has no enabled key, because -o and --report select it.",
		Properties:           known,
		AdditionalProperties: jsonschema.FalseSchema,
	}
	if s.Properties == nil {
		return nil, fmt.Errorf("config schema has no properties")
	}
	s.Properties.Set("plugins", pluginsSchema)
	return json.MarshalIndent(s, "", "  ")
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}
