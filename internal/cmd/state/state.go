// Package state holds the "vet state" commands, which show and delete the
// local scan state and the enrichment cache.
package state

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	vstate "github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui"
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
func bytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}
