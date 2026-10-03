package report

import (
	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/runner"
)

func newShow(a *app.App) *cobra.Command {
	var o runner.ShowOptions
	c := &cobra.Command{
		Use:   "show [ID|FILE]",
		Short: "Render a saved report",
		Long: `Render a saved scan in any -o format, with no new scan. The default is the
last completed scan of the current directory, or of its nearest parent
that has a scan. Name a scan by a unique prefix of its id, by "last", or
by a report file that "vet scan -o json" or "-o jsonl" wrote.

--fail-on and --policy apply a new gate to the saved report, which tests
a policy against a scan. The saved scan does not change. The exit code
follows the gate of the rendered report.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				o.Ref = args[0]
			}
			return runner.Show(cmd.Context(), a, o)
		},
	}
	f := c.Flags()
	f.StringVar(&o.FailOn, "fail-on", "", "Apply a gate that fails on a finding at this severity or above")
	f.StringVar(&o.Policy, "policy", "", "Apply this policy v2 file, directory or name")
	f.StringArrayVar(&o.Reports, "report", nil, "Also write the report as FORMAT=PATH. Repeatable")
	f.BoolVar(&o.All, "all", false, "Show each finding on its own row in the table, with no row limit")
	f.StringVar(&o.State.StateDir, "state-dir", "", "Directory of the scan index and the scan files")
	return c
}
