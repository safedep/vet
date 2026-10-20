package report

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/runner"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/printer"
	"github.com/safedep/vet/v2/report"
)

func newRoot(a *app.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "root",
		Short: "Read the entry points of the call graph of a saved scan",
		Long: `Read the entry points where the call graph search of a saved scan
started: the main functions, the framework handlers, the tests and the
entry points that --entrypoint names. A scan at the function level of
reach searches the call graph of a Go or Rust project.`,
	}
	c.AddCommand(newRootList(a))
	return c
}

func newRootList(a *app.App) *cobra.Command {
	var scan string
	var f state.Flags
	c := &cobra.Command{
		Use:   "list",
		Short: "List the entry points of the call graph of a saved scan",
		Long: `List the entry points of the last scan of the current directory, with
the kind, the file and the line of each one. Use the list to find a
missing entry point, then add it with --entrypoint path:function. --scan
names another scan. -o json prints the whole list.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			doc, err := runner.Load(cmd.Context(), a, scan, f)
			if err != nil {
				return err
			}
			var roots *report.ReachRoots
			if r := doc.Header().Scan.Reach; r != nil {
				roots = r.Roots
			}
			p, err := a.Printer()
			if err != nil {
				return err
			}
			return p.Print(roots, rootRows(roots))
		},
	}
	c.Flags().StringVar(&scan, "scan", "", "Scan id prefix, last, or report file. The default is the last scan")
	c.Flags().StringVar(&f.StateDir, "state-dir", "", "Directory of the scan index and the scan files")
	return c
}

func rootRows(roots *report.ReachRoots) printer.Rows {
	rows := printer.Rows{
		Headers: []string{"KIND", "FUNCTION", "WHERE", "RULE"},
		Empty:   "The scan searched no call path. A scan with --reach function of a Go or Rust project with a vulnerability searches it.",
	}
	switch {
	case roots == nil:
		return rows
	case roots.Fallback:
		rows.Empty = fmt.Sprintf("vet found no entry point, so the search started from each of the %d exported functions. Add one with --entrypoint path:function.", roots.Total)
		return rows
	}
	for _, r := range roots.List {
		where := r.File
		if r.Line > 0 {
			where = fmt.Sprintf("%s:%d", r.File, r.Line)
		}
		rows.Rows = append(rows.Rows, []string{r.Kind, escape.Line(r.Function), escape.Line(where), escape.Line(r.Rule)})
	}
	if more := roots.Total - len(roots.List); more > 0 {
		rows.Footer = fmt.Sprintf("The scan lists the first %d entry points. It has %d more.", len(roots.List), more)
	}
	return rows
}
