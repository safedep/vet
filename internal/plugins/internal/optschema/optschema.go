// Package optschema generates the JSON Schema of the options of a plugin,
// for plugin.Schemer and "vet config schema get".
package optschema

import (
	"encoding/json"

	"github.com/invopop/jsonschema"
)

// Of returns the JSON Schema of an options struct. An unknown option is an
// error in the plugin factory, so the schema allows no other property.
func Of(v any) []byte {
	r := &jsonschema.Reflector{DoNotReference: true, AllowAdditionalProperties: false, ExpandedStruct: true, RequiredFromJSONSchemaTags: true}
	s := r.Reflect(v)
	s.Version = ""
	b, err := json.Marshal(s)
	if err != nil {
		// The options structs are plain data, so Marshal does not fail.
		panic(err)
	}
	return b
}
