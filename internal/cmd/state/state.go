// Package state holds the "vet state" commands, which show and delete the
// local scan state and the enrichment cache.
package state

import (
	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	vstate "github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/humanize"
)

// New returns the "vet state" command.
func New(a *app.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "state",
		Short: "Show and delete the local scan state",
		Long: `vet keeps each scan in the state directory and the enrichment results in the
cache directory, and deletes old scans by its retention rules. The state
commands show the directories, the scans and the cache, and delete scans
or the cache.`,
	}
	c.AddCommand(newShow(a), newDelete(a))
	return c
}

func closeStore(s *vstate.Store) {
	if err := s.Close(); err != nil {
		tui.Warning("close the scan index: %v", err)
	}
}

// bytes formats a size, for example 12.5 MB.
var bytes = humanize.Bytes
