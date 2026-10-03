package report

import (
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/runner"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/humanize"
	"github.com/safedep/vet/v2/internal/tui/printer"
	"github.com/safedep/vet/v2/internal/tui/table"
)

// Scan is one row of "vet report list".
type Scan struct {
	ID         string    `json:"id"`
	Target     string    `json:"target"`
	TargetKey  string    `json:"target_key"`
	Kind       string    `json:"kind"`
	Status     string    `json:"status"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitzero"`
	RunTime    string    `json:"run_time"`
	Continued  bool      `json:"continued"`
	Packages   int       `json:"packages"`
	Findings   int       `json:"findings"`
	Gate       string    `json:"gate,omitempty"`
	SizeBytes  int64     `json:"size_bytes"`
}

func newList(a *app.App) *cobra.Command {
	var all bool
	var f state.Flags
	c := &cobra.Command{
		Use:   "list",
		Short: "List the saved scans of the current directory",
		Long: `List the saved scans of the current directory, or of its nearest parent
that has a scan, the newest first, with the status, the counts and the
gate of each. --all lists the scans of every target.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			_, s, err := runner.Store(ctx, a, f)
			if err != nil {
				return err
			}
			defer closeStore(s)
			var es []*state.IndexEntry
			if all {
				es, err = s.Index().List(ctx, state.ListOptions{})
			} else {
				es, err = runner.TargetScans(ctx, s)
			}
			if err != nil {
				return err
			}
			p, err := a.Printer()
			if err != nil {
				return err
			}
			scans, rows := listRows(es, time.Now())
			return p.Print(scans, rows)
		},
	}
	c.Flags().BoolVar(&all, "all", false, "List the scans of every target")
	c.Flags().StringVar(&f.StateDir, "state-dir", "", "Directory of the scan index and the scan files")
	return c
}

func listRows(es []*state.IndexEntry, now time.Time) ([]Scan, printer.Rows) {
	scans := make([]Scan, 0, len(es))
	rows := printer.Rows{
		Headers: []string{"SCAN", "TARGET", "STARTED", "DURATION", "STATUS", "PACKAGES", "FINDINGS", "GATE"},
		Columns: []table.Column{
			{Fit: table.Keep},
			{Fit: table.CutLeft},
			{Fit: table.Keep},
			{Drop: 1},
			{Drop: 2},
			{Fit: table.Keep},
			{Fit: table.Keep},
			{Fit: table.Keep},
		},
		Empty: "No saved scan. Run vet scan.",
	}
	for _, e := range es {
		s := Scan{
			ID: e.ID, Target: e.TargetLabel, TargetKey: e.TargetKey, Kind: e.Kind, Status: string(e.Status),
			StartedAt: e.StartedAt, FinishedAt: e.FinishedAt, RunTime: e.RunTime.Round(time.Second).String(),
			Continued: e.Continued, Packages: e.Packages, Findings: e.Findings, Gate: e.Gate, SizeBytes: e.SizeBytes,
		}
		scans = append(scans, s)
		status, packages, findings, gate := s.Status, "-", "-", "-"
		if e.Continued {
			status += " (continued)"
		}
		if e.Status == state.StatusCompleted {
			packages, findings, gate = strconv.Itoa(e.Packages), strconv.Itoa(e.Findings), e.Gate
		}
		rows.Rows = append(rows.Rows, []string{
			shortID(e.ID), escape.Line(e.TargetKey), humanize.Time(e.StartedAt, now), s.RunTime, status, packages, findings, gate,
		})
	}
	return scans, rows
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
