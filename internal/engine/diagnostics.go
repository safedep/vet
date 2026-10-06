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

// diagnostics counts the diagnostics of a run, so that one problem that
// repeats, such as a backend that does not answer, gives one record.
type diagnostics struct {
	mu    sync.Mutex
	byKey map[string]*report.Diagnostic
	order []string
	total int
}

func newDiagnostics() *diagnostics {
	return &diagnostics{byKey: map[string]*report.Diagnostic{}}
}

func (d *diagnostics) add(level report.DiagnosticLevel, code, component, msg string) {
	d.put(&report.Diagnostic{Level: level, Code: code, Component: component, Message: msg})
}

func (d *diagnostics) put(diag *report.Diagnostic) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.total++
	key := strings.Join([]string{string(diag.Level), diag.Code, diag.Component, string(diag.Change), diag.Message}, "\x00")
	if prev, ok := d.byKey[key]; ok {
		prev.Count++
		return
	}
	diag.Count = 1
	d.byKey[key] = diag
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
		errs = append(errs, scan.AddDiagnostic(ctx, d.byKey[k]))
	}
	d.byKey, d.order = map[string]*report.Diagnostic{}, nil
	return errors.Join(errs...)
}
