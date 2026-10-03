// Package report holds the "vet report" commands, which read saved scans.
package report

import (
	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui"
)

// New returns the "vet report" command.
func New(a *app.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "report",
		Short: "Read the reports of saved scans",
		Long: `vet saves each scan. The report commands render a saved scan in any
format, apply a new gate to it, list the scans, compare two scans, show one
finding, list the AI and crypto capabilities and print the JSON Schema of
the report. They make no new scan.`,
	}
	c.AddCommand(newShow(a), newList(a), newDiff(a), newFinding(a), newCapability(a), newSchema(a))
	return c
}

func closeStore(s *state.Store) {
	if err := s.Close(); err != nil {
		tui.Warning("close the scan index: %v", err)
	}
}
