// Package report holds the "vet report" commands, which read saved scans.
package report

import (
	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
)

// New returns the "vet report" command.
func New(a *app.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "report",
		Short: "Read the reports of saved scans",
		Long: `vet saves each scan. The report commands render a saved scan in any
format, apply a new gate to it, list the scans, compare two scans, show one
finding and print the JSON Schema of the report. They make no new scan.`,
	}
	c.AddCommand(newShow(a))
	return c
}
