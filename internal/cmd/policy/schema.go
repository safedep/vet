package policy

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/policy"
	"github.com/safedep/vet/v2/internal/tui/output"
)

func newSchemaGet(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Print the JSON Schema of the rule input",
		Long: `Print the JSON Schema of the variables that a policy rule reads: finding,
package and manifest. An optional field with no value is absent, so a rule
tests it with has(), for example has(package.days_since_publish).`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if out := a.Globals.Output; out != "" && out != "json" {
				return app.UsageError(fmt.Sprintf("-o %s: the schema is JSON only", out), "Use -o json, or no -o.")
			}
			b, err := policy.InputSchema()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(output.Stdout(), string(b))
			return err
		},
	}
}
