package acceptance

import (
	"strings"

	"github.com/rogpeppe/go-internal/testscript"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// cmdSchemaCheck validates a JSON document against a JSON Schema:
// schemacheck <schema file> <file|stdout>.
func cmdSchemaCheck(ts *testscript.TestScript, neg bool, args []string) {
	if len(args) != 2 {
		ts.Fatalf("usage: schemacheck <schema file> <file|stdout>")
	}
	schemaDoc, err := jsonschema.UnmarshalJSON(strings.NewReader(ts.ReadFile(args[0])))
	ts.Check(err)
	c := jsonschema.NewCompiler()
	const url = "file:///schema.json"
	ts.Check(c.AddResource(url, schemaDoc))
	sch, err := c.Compile(url)
	ts.Check(err)
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(ts.ReadFile(args[1])))
	ts.Check(err)
	err = sch.Validate(inst)
	switch {
	case err != nil && !neg:
		ts.Fatalf("%s does not validate against %s: %v", args[1], args[0], err)
	case err == nil && neg:
		ts.Fatalf("%s validates against %s", args[1], args[0])
	}
}
