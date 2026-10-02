package state

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/plugins/sources/dir"
	"github.com/safedep/vet/v2/internal/runner"
	vstate "github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/printer"
)

// Deletion is the output of "vet state delete".
type Deletion struct {
	DryRun    bool          `json:"dry_run"`
	Scans     []DeletedScan `json:"scans"`
	Cache     bool          `json:"cache"`
	SizeBytes int64         `json:"size_bytes"`
}

// DeletedScan is a scan that the command deletes.
type DeletedScan struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	Status    string    `json:"status"`
	StartedAt time.Time `json:"started_at"`
	SizeBytes int64     `json:"size_bytes"`
}

type deleteOptions struct {
	target, scan, olderThan string
	interrupted, cache, all bool
	dryRun, yes             bool
	state                   vstate.Flags
}

func newDelete(a *app.App) *cobra.Command {
	var o deleteOptions
	c := &cobra.Command{
		Use:   "delete",
		Short: "Delete scans or the enrichment cache",
		Long: `Delete saved scans or the enrichment cache. With no selector, vet deletes
the scans that the retention rules select now. The selectors combine: a
scan must match each one. vet never deletes a scan that a vet process
runs.

vet asks before it deletes. In agent mode, with --no-input or with no
terminal, vet cannot ask: pass --yes, or the command exits 2. --dry-run
shows what vet would delete and deletes nothing.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runDelete(cmd, a, o) },
	}
	f := c.Flags()
	f.StringVar(&o.target, "target", "", "Delete the scans of this target, a directory or a target key")
	f.StringVar(&o.scan, "scan", "", "Delete the scan with this id prefix")
	f.StringVar(&o.olderThan, "older-than", "", "Delete the scans that started before this age, for example 7d")
	f.BoolVar(&o.interrupted, "interrupted", false, "Delete interrupted scans only")
	f.BoolVar(&o.cache, "cache", false, "Delete the enrichment cache")
	f.BoolVar(&o.all, "all", false, "Delete every scan and the cache. The index stays, empty")
	f.BoolVar(&o.dryRun, "dry-run", false, "Show what vet would delete, and delete nothing")
	f.BoolVar(&o.yes, "yes", false, "Do not ask before the delete")
	f.StringVar(&o.state.StateDir, "state-dir", "", "Directory of the scan index and the scan files")
	f.StringVar(&o.state.CacheDir, "cache-dir", "", "Directory of the enrichment cache")
	return c
}

func runDelete(cmd *cobra.Command, a *app.App, o deleteOptions) error {
	ctx := cmd.Context()
	rt, s, err := runner.Store(ctx, a, o.state)
	if err != nil {
		return err
	}
	defer closeStore(s)

	scans, err := selectScans(cmd, rt.Config, s, o)
	if err != nil {
		return err
	}
	d := Deletion{DryRun: o.dryRun, Scans: []DeletedScan{}, Cache: o.cache || o.all}
	for _, e := range scans {
		size := vstate.FilesSize([]string{e.File, e.File + "-wal"})
		d.Scans = append(d.Scans, DeletedScan{ID: e.ID, Target: e.TargetKey, Status: string(e.Status), StartedAt: e.StartedAt, SizeBytes: size})
		d.SizeBytes += size
	}
	if d.Cache {
		d.SizeBytes += vstate.FilesSize(vstate.CacheFiles(rt.Dirs.Cache))
	}

	p, err := a.Printer()
	if err != nil {
		return err
	}
	if len(d.Scans) == 0 && !d.Cache {
		tui.Info("Nothing to delete.")
		return p.Print(d, deleteRows(d))
	}
	if !o.dryRun && !o.yes {
		what := fmt.Sprintf("%d scans", len(d.Scans))
		if d.Cache {
			what += " and the enrichment cache"
		}
		ok, err := a.Confirm(fmt.Sprintf("Delete %s (%s)?", what, bytes(d.SizeBytes)), "--yes")
		if err != nil {
			return err
		}
		if !ok {
			tui.Info("Deleted nothing.")
			return nil
		}
	}
	if !o.dryRun {
		for _, e := range scans {
			if err := s.DeleteScan(ctx, e); err != nil {
				return err
			}
		}
		if d.Cache {
			if err := vstate.RemoveFiles(vstate.CacheFiles(rt.Dirs.Cache)); err != nil {
				return err
			}
		}
	}
	if err := p.Print(d, deleteRows(d)); err != nil {
		return err
	}
	if o.dryRun {
		tui.Info("vet would delete %d scans and free %s. Run without --dry-run to delete them.", len(d.Scans), bytes(d.SizeBytes))
	} else {
		tui.Success("Deleted %d scans. Freed %s.", len(d.Scans), bytes(d.SizeBytes))
	}
	return nil
}

// selectScans applies the selectors. With none, the retention rules
// select. A running scan of a live process never matches.
func selectScans(cmd *cobra.Command, cfg *config.Config, s *vstate.Store, o deleteOptions) ([]*vstate.IndexEntry, error) {
	ctx := cmd.Context()
	if o.target == "" && o.scan == "" && o.olderThan == "" && !o.interrupted && !o.all {
		if o.cache {
			return nil, nil
		}
		r, err := runner.RetentionOf(cfg)
		if err != nil {
			return nil, err
		}
		entries, err := s.Index().List(ctx, vstate.ListOptions{})
		if err != nil {
			return nil, err
		}
		return r.Select(entries, time.Now()), nil
	}
	var cutoff time.Time
	if o.olderThan != "" {
		d, err := config.Duration(o.olderThan).Value()
		if err != nil || d <= 0 {
			return nil, app.UsageError(fmt.Sprintf("--older-than %q is not a duration", o.olderThan), "Use a duration such as 12h or 7d.")
		}
		cutoff = time.Now().Add(-d)
	}
	target := o.target
	if target != "" {
		if info, err := os.Stat(target); err == nil && info.IsDir() {
			if key, err := dir.Canonical(target); err == nil {
				target = key
			}
		}
	}
	entries, err := s.Index().List(ctx, vstate.ListOptions{})
	if err != nil {
		return nil, err
	}
	var out []*vstate.IndexEntry
	for _, e := range entries {
		switch {
		case e.Status == vstate.StatusRunning:
			continue
		case target != "" && e.TargetKey != target:
			continue
		case o.scan != "" && !strings.HasPrefix(e.ID, o.scan):
			continue
		case !cutoff.IsZero() && !e.StartedAt.Before(cutoff):
			continue
		case o.interrupted && e.Status != vstate.StatusInterrupted:
			continue
		}
		out = append(out, e)
	}
	return out, nil
}

func deleteRows(d Deletion) printer.Rows {
	rows := printer.Rows{Headers: []string{"SCAN", "TARGET", "STATUS", "SIZE"}, Empty: "No scan to delete."}
	for _, s := range d.Scans {
		rows.Rows = append(rows.Rows, []string{s.ID, escape.Line(s.Target), s.Status, bytes(s.SizeBytes)})
	}
	if d.Cache {
		rows.Rows = append(rows.Rows, []string{"cache", "-", "-", "-"})
	}
	return rows
}
