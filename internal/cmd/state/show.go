package state

import (
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/config/appdir"
	"github.com/safedep/vet/v2/internal/runner"
	vstate "github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/humanize"
	"github.com/safedep/vet/v2/internal/tui/printer"
	"github.com/safedep/vet/v2/internal/tui/table"
)

// Show is the output of "vet state show".
type Show struct {
	StateDir       string        `json:"state_dir"`
	StateDirOrigin string        `json:"state_dir_origin"`
	CacheDir       string        `json:"cache_dir"`
	CacheDirOrigin string        `json:"cache_dir_origin"`
	Scans          int           `json:"scans"`
	Targets        int           `json:"targets"`
	SizeBytes      int64         `json:"size_bytes"`
	Interrupted    []Interrupted `json:"interrupted"`
	Cache          CacheInfo     `json:"cache"`
	Retention      RetentionInfo `json:"retention"`
}

// Interrupted is a scan that can continue.
type Interrupted struct {
	ID        string    `json:"id"`
	Target    string    `json:"target"`
	UpdatedAt time.Time `json:"updated_at"`
}

// CacheInfo describes the enrichment cache.
type CacheInfo struct {
	Entries   int       `json:"entries"`
	SizeBytes int64     `json:"size_bytes"`
	Oldest    time.Time `json:"oldest,omitzero"`
}

// RetentionInfo holds the retention rules.
type RetentionInfo struct {
	PerTarget   int    `json:"per_target"`
	Interrupted string `json:"interrupted"`
	MaxSize     string `json:"max_size"`
}

func newShow(a *app.App) *cobra.Command {
	var f vstate.Flags
	c := &cobra.Command{
		Use:   "show",
		Short: "Show the state and cache directories, the scans and the retention rules",
		Long: `Show where vet keeps its state and its cache and why, how many scans it
keeps and their size, the interrupted scans that can continue, the size of
the enrichment cache, and the retention rules.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			rt, s, err := runner.Store(ctx, a, f)
			if err != nil {
				return err
			}
			defer closeStore(s)
			u, err := s.Usage(ctx)
			if err != nil {
				return err
			}
			cfg := rt.Config.State.Retention
			out := Show{
				StateDir: rt.Dirs.State, StateDirOrigin: rt.Dirs.Origin[appdir.State],
				CacheDir: rt.Dirs.Cache, CacheDirOrigin: rt.Dirs.Origin[appdir.Cache],
				Scans: u.Scans, Targets: u.Targets, SizeBytes: u.Bytes, Interrupted: []Interrupted{},
				Retention: RetentionInfo{PerTarget: cfg.PerTarget, Interrupted: string(cfg.Interrupted), MaxSize: string(cfg.MaxSize)},
			}
			for _, e := range u.Interrupted {
				out.Interrupted = append(out.Interrupted, Interrupted{ID: e.ID, Target: e.TargetKey, UpdatedAt: e.UpdatedAt})
			}
			out.Cache.SizeBytes = vstate.FilesSize(vstate.CacheFiles(rt.Dirs.Cache))
			if out.Cache.SizeBytes > 0 {
				c, err := vstate.OpenCache(ctx, rt.Dirs.Cache)
				if err != nil {
					return err
				}
				st, err := c.Stats(ctx)
				if cerr := c.Close(); err == nil {
					err = cerr
				}
				if err != nil {
					return err
				}
				out.Cache.Entries, out.Cache.Oldest = st.Entries, st.Oldest
			}
			p, err := a.Printer()
			if err != nil {
				return err
			}
			return p.Print(out, showRows(out, time.Now()))
		},
	}
	c.Flags().StringVar(&f.StateDir, "state-dir", "", "Directory of the scan index and the scan files")
	c.Flags().StringVar(&f.CacheDir, "cache-dir", "", "Directory of the enrichment cache")
	return c
}

func showRows(s Show, now time.Time) printer.Rows {
	rows := printer.Rows{Headers: []string{"ITEM", "VALUE"}, Columns: []table.Column{{Fit: table.Keep}, {Fit: table.Wrap}}}
	add := func(k, v string) { rows.Rows = append(rows.Rows, []string{k, v}) }
	add("State directory", escape.Line(s.StateDir)+" ("+s.StateDirOrigin+")")
	add("Cache directory", escape.Line(s.CacheDir)+" ("+s.CacheDirOrigin+")")
	add("Scans", strconv.Itoa(s.Scans)+" across "+strconv.Itoa(s.Targets)+" targets, "+bytes(s.SizeBytes))
	for _, i := range s.Interrupted {
		add("Interrupted", i.ID+", "+escape.Line(i.Target)+", "+humanize.Time(i.UpdatedAt, now))
	}
	cache := strconv.Itoa(s.Cache.Entries) + " entries, " + bytes(s.Cache.SizeBytes)
	if !s.Cache.Oldest.IsZero() {
		cache += ", oldest " + humanize.Time(s.Cache.Oldest, now)
	}
	add("Enrichment cache", cache)
	add("Retention", strconv.Itoa(s.Retention.PerTarget)+" scans per target, interrupted scans "+
		s.Retention.Interrupted+", "+s.Retention.MaxSize+" in total")
	return rows
}
