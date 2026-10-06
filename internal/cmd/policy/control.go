package policy

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/internal/tui/printer"
	"github.com/safedep/vet/v2/internal/tui/table"
)

func newControlList(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the controls of vet and their default severities",
		Long: `List each control id of vet, with the plugin that emits it, its family,
its default severity and what it checks. A rule matches a control id, a
suppression names one, and --fail-on uses the default severities. A
finding can have another severity, for example a vulnerability takes the
severity of its advisory.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			list, err := controls.Catalog()
			if err != nil {
				return err
			}
			p, err := a.Printer()
			if err != nil {
				return err
			}
			rows := printer.Rows{
				Headers: []string{"CONTROL", "PLUGIN", "FAMILY", "SEVERITY", "TITLE"},
				Columns: []table.Column{{Fit: table.Keep}, {Drop: 1}, {Drop: 2}, {Fit: table.Keep}},
			}
			for _, c := range list {
				rows.Rows = append(rows.Rows, []string{c.ID, c.Plugin, string(c.Family), string(c.Severity), c.Title})
			}
			return p.Print(list, rows)
		},
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
