package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/plugins/sources/dir"
	"github.com/safedep/vet/v2/internal/policy"
	"github.com/safedep/vet/v2/internal/reportdoc"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/view"
	"github.com/safedep/vet/v2/report"
)

// Last names the last completed scan of the current target.
const Last = "last"

// CodeNoScan is the error code of a scan reference that names no scan.
// The command exits with code 2.
const CodeNoScan = "usage_no_scan"

// Store opens the state of the run for a command that reads it.
func Store(ctx context.Context, a *app.App, f state.Flags) (*config.Runtime, *state.Store, error) {
	rt, err := a.Config(app.ConfigOptions{StateDir: f.StateDir, CacheDir: f.CacheDir})
	if err != nil {
		return nil, nil, err
	}
	s, err := state.Open(ctx, state.Options{StateDir: rt.Dirs.State, CacheDir: rt.Dirs.Cache})
	if err != nil {
		return nil, nil, err
	}
	return rt, s, nil
}

// TargetScans returns the scans of the current target with a status, the
// newest first. The current target is the working directory, or its
// nearest parent that has a scan, as git finds .git.
func TargetScans(ctx context.Context, s *state.Store, statuses ...state.Status) ([]*state.IndexEntry, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	d, err := dir.Canonical(wd)
	if err != nil {
		return nil, err
	}
	for {
		es, err := s.Index().List(ctx, state.ListOptions{TargetKey: d, Statuses: statuses})
		if err != nil {
			return nil, err
		}
		if len(es) > 0 {
			return es, nil
		}
		parent := filepath.Dir(d)
		if parent == d {
			return nil, nil
		}
		d = parent
	}
}

// Resolve finds the scan that a reference names: "" or "last" for the
// last completed scan of the current target, or a unique prefix of an id.
func Resolve(ctx context.Context, s *state.Store, ref string) (*state.IndexEntry, error) {
	if ref == "" || ref == Last {
		es, err := TargetScans(ctx, s, state.StatusCompleted)
		if err != nil {
			return nil, err
		}
		if len(es) == 0 {
			return nil, noScan("no completed scan of this directory", "Run vet scan, or name a scan id. vet report list --all lists every scan.")
		}
		return es[0], nil
	}
	e, err := s.Index().Find(ctx, ref)
	switch {
	case errors.Is(err, state.ErrNotFound):
		return nil, noScan(fmt.Sprintf("no scan has the id %q", ref), "vet report list --all lists every scan.")
	case err != nil:
		return nil, noScan(err.Error(), "Type more characters of the id.")
	}
	return e, nil
}

func noScan(msg, help string) error {
	return app.UsageErrorCode(CodeNoScan, msg, help)
}

// Load reads a saved report into memory. ref is a scan reference, a scan
// file (.db) or a report file in the json or jsonl format.
func Load(ctx context.Context, a *app.App, ref string, f state.Flags) (*reportdoc.Doc, error) {
	if info, err := os.Stat(ref); err == nil && !info.IsDir() {
		return loadFile(ctx, ref)
	}
	_, s, err := Store(ctx, a, f)
	if err != nil {
		return nil, err
	}
	defer closeWarn("the scan index", s.Close)
	e, err := Resolve(ctx, s, ref)
	if err != nil {
		return nil, err
	}
	if e.Status != state.StatusCompleted {
		return nil, noScan(fmt.Sprintf("scan %s is %s, not completed", e.ID, e.Status), "Run vet scan to continue it.")
	}
	scan, err := s.OpenScan(ctx, e)
	if err != nil {
		return nil, err
	}
	defer closeWarn("the scan file", scan.Close)
	return reportdoc.Load(ctx, scan)
}

func loadFile(ctx context.Context, path string) (*reportdoc.Doc, error) {
	if strings.EqualFold(filepath.Ext(path), ".db") {
		scan, err := state.OpenScanFile(ctx, path)
		if err != nil {
			return nil, err
		}
		defer closeWarn("the scan file", scan.Close)
		return reportdoc.Load(ctx, scan)
	}
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer closeWarn(path, fh.Close)
	d, err := report.Read(fh)
	if err != nil {
		return nil, app.UsageErrorCode(CodeNoScan, fmt.Sprintf("%s is not a vet report: %v", path, err),
			"Name a report that vet scan -o json or -o jsonl wrote, a scan id, or last.")
	}
	return reportdoc.FromDocument(d), nil
}

// ShowOptions are the inputs of "vet report show".
type ShowOptions struct {
	Ref     string
	FailOn  string
	Policy  string
	Reports []string
	// All shows every finding in the table.
	All   bool
	State state.Flags
}

// Show renders a saved report. --fail-on and --policy, or their config
// keys, apply a new gate in memory. The saved scan does not change.
func Show(ctx context.Context, a *app.App, o ShowOptions) error {
	rt, err := a.Config(app.ConfigOptions{StateDir: o.State.StateDir, CacheDir: o.State.CacheDir})
	if err != nil {
		return err
	}
	settings, err := policy.ResolveSettings(o.FailOn, o.Policy, rt.Config.Policy)
	if err != nil {
		return err
	}
	var extra map[string]map[string]any
	if o.All {
		extra = map[string]map[string]any{"table": {"all": true}}
	}
	outs, err := Outputs(rt.Config, a.Globals.Output, o.Reports, extra)
	if err != nil {
		return err
	}
	doc, err := Load(ctx, a, o.Ref, o.State)
	if err != nil {
		return err
	}
	if settings.FailOn != "" || settings.File != "" {
		e, err := newEvaluator(ctx, rt.Config, settings)
		if err != nil {
			return err
		}
		g, err := e.Finalize(ctx, doc)
		if err != nil {
			return err
		}
		doc.SetGate(g, time.Now())
	}
	return Render(ctx, doc, view.NewScan(view.Options{Saved: true}), outs)
}
