package policy

import (
	"strconv"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/internal/tui/printer"
	"github.com/safedep/vet/v2/internal/tui/table"
	"github.com/safedep/vet/v2/plugin"
)

// Control is one row of "vet policy control list".
type Control struct {
	ID          string `json:"id"`
	Plugin      string `json:"plugin"`
	Family      string `json:"family"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
}

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
			list, err := List()
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
				rows.Rows = append(rows.Rows, []string{c.ID, c.Plugin, c.Family, c.Severity, c.Title})
			}
			return p.Print(list, rows)
		},
	}
}

// List returns the controls of the built-in control plugins.
func List() ([]Control, error) {
	var out []Control
	for _, spec := range controls.Builtin() {
		c, err := spec.New(plugin.MapConfig(nil))
		if err != nil {
			return nil, err
		}
		d, ok := c.(plugin.Describer)
		if !ok {
			continue
		}
		for _, info := range d.Controls() {
			out = append(out, Control{
				ID: info.ID, Plugin: spec.Name, Family: string(info.Family), Severity: string(info.Severity),
				Title: info.Title, Description: info.Description,
			})
		}
	}
	return out, nil
}

func itoa(n int) string { return strconv.Itoa(n) }
