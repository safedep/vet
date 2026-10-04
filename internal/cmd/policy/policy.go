// Package policy holds the "vet policy" commands: the policy file, the
// controls that its rules name, and the schema of the rule input.
package policy

import (
	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
)

// New returns the "vet policy" command.
func New(a *app.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "policy",
		Short: "Write and check policy v2 files",
		Long: `A policy v2 file holds rules and suppressions. A rule is a CEL condition
over vet's finding, package and manifest types, with the action fail or
warn. A suppression hides findings from the gate, with a reason and an
optional expiry. vet scan --policy and vet report show --policy apply it.`,
	}
	control := &cobra.Command{
		Use:   "control",
		Short: "Read the controls of vet",
		Long:  `Read the controls of vet. A rule or a suppression of a policy names a control by its id.`,
	}
	control.AddCommand(newControlList(a))
	schema := &cobra.Command{
		Use:   "schema",
		Short: "Read the JSON Schema of the rule input",
		Long:  `Read the JSON Schema of the finding, package and manifest variables that a rule reads.`,
	}
	schema.AddCommand(newSchemaGet(a))
	c.AddCommand(newInit(a), newValidate(a), control, schema)
	return c
}
