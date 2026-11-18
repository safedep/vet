package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"

	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/report"
)

// stageRun names the diagnostics that each run writes again: those of the
// caller, of the walk, and of the base of a pull request scan. A continued
// scan replaces those of the earlier run.
const stageRun = "run"

// diagnostics counts the diagnostics of a run, so that one problem that
// repeats, such as a backend that does not answer, gives one record.
type diagnostics struct {
	mu    sync.Mutex
	byKey map[string]staged
	order []string
	total int
}

// staged is a diagnostic and the stage whose work writes it again in a
// continued scan. An empty stage keeps the diagnostic.
type staged struct {
	stage string
	diag  *report.Diagnostic
}

func newDiagnostics() *diagnostics {
	return &diagnostics{byKey: map[string]staged{}}
}

func (d *diagnostics) add(level report.DiagnosticLevel, code, component, msg string) {
	d.addIn("", level, code, component, msg)
}

func (d *diagnostics) addIn(stage string, level report.DiagnosticLevel, code, component, msg string) {
	d.putIn(stage, &report.Diagnostic{Level: level, Code: code, Component: component, Message: msg})
}

func (d *diagnostics) put(diag *report.Diagnostic) {
	d.putIn("", diag)
}

func (d *diagnostics) putIn(stage string, diag *report.Diagnostic) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.total++
	key := strings.Join([]string{stage, string(diag.Level), diag.Code, diag.Component, string(diag.Change), diag.Message}, "\x00")
	if prev, ok := d.byKey[key]; ok {
		prev.diag.Count++
		return
	}
	diag.Count = 1
	d.byKey[key] = staged{stage: stage, diag: diag}
	d.order = append(d.order, key)
}

// flush writes the diagnostics to the scan file in a stable order.
func (d *diagnostics) flush(ctx context.Context, scan *state.Scan) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	keys := slices.Clone(d.order)
	slices.Sort(keys)
	var errs []error
	for _, k := range keys {
		s := d.byKey[k]
		errs = append(errs, scan.AddStageDiagnostic(ctx, s.stage, s.diag))
	}
	d.byKey, d.order = map[string]staged{}, nil
	return errors.Join(errs...)
}
