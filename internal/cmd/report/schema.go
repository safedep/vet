package report

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/report"
)

func newSchema(a *app.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "schema",
		Short: "Read the JSON Schema of the report",
		Long:  `Read the JSON Schema of the report that -o json writes, for scripts, editors and agents.`,
	}
	c.AddCommand(&cobra.Command{
		Use:   "get",
		Short: "Print the JSON Schema of the report",
		Long: `Print the JSON Schema of the report document that -o json writes. vet
generates it from its Go types. Each JSON line of -o jsonl names the same
schema in its $schema field.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if out := a.Globals.Output; out != "" && out != "json" {
				return app.UsageError(fmt.Sprintf("-o %s: the schema is JSON only", out), "Use -o json, or no -o.")
			}
			b, err := report.Schema()
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(output.Stdout(), string(b))
			return err
		},
	})
	return c
}
