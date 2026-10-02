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

// Diagnostic codes of the engine.
const (
	CodeExtractFailed      = "extract_failed"
	CodeUnknownEcosystem   = "unknown_ecosystem"
	CodeEnrichUnavailable  = "enrich_unavailable"
	CodeEnrichFailed       = "enrich_failed"
	CodeControlUnavailable = "control_unavailable"
	CodeControlFailed      = "control_failed"
	CodeInvalidFinding     = "invalid_finding"
)

// diagnostics counts the diagnostics of a run, so that one problem that
// repeats, such as a backend that does not answer, gives one record.
type diagnostics struct {
	mu     sync.Mutex
	byKey  map[string]*report.Diagnostic
	order  []string
	errors int
}

func newDiagnostics() *diagnostics {
	return &diagnostics{byKey: map[string]*report.Diagnostic{}}
}

func (d *diagnostics) add(level report.DiagnosticLevel, code, component, msg string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if level == report.DiagnosticError {
		d.errors++
	}
	key := strings.Join([]string{string(level), code, component, msg}, "\x00")
	if prev, ok := d.byKey[key]; ok {
		prev.Count++
		return
	}
	d.byKey[key] = &report.Diagnostic{Level: level, Code: code, Component: component, Message: msg, Count: 1}
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
