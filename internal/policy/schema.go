package policy

import (
	"encoding/json"

	"github.com/invopop/jsonschema"
)

// SchemaURL is the id of the policy input schema.
const SchemaURL = "https://schemas.safedep.io/vet/policy-input/v2.json"

// InputSchema returns the JSON Schema of the rule input, generated from
// the Go types. "vet policy schema get" prints it.
func InputSchema() ([]byte, error) {
	r := &jsonschema.Reflector{AllowAdditionalProperties: true}
	s := r.Reflect(&Input{})
	s.ID = SchemaURL
	s.Title = "vet policy input"
	s.Description = "The variables that a policy v2 rule reads: finding, package and manifest."
	return json.MarshalIndent(s, "", "  ")
}
