package inventory

import (
	"context"
	"fmt"

	"github.com/safedep/vet/pkg/common/logger"
)

// Orchestrator wires Scanners and Sinks into a single-goroutine producer
// pipeline.
//
// The orchestrator is not safe for concurrent Run calls; instantiate one per
// scan.
type Orchestrator struct {
	scanners []Scanner
	sinks    []Sink
}

// New constructs an Orchestrator over a fixed scanner and sink registration
// order. Both slices may be nil or empty; the orchestrator's lifecycle still
// completes correctly (sinks see Begin/End/Close with an empty summary).
func New(scanners []Scanner, sinks []Sink) *Orchestrator {
	return &Orchestrator{scanners: scanners, sinks: sinks}
}

// Run executes one full scan: Begin on every sink, scanners in registration
// order with items fanned to all sinks, then End and Close on every sink.
//
// Errors in scanners and in Sink.Emit are captured into the ScanSummary;
// the scan continues. Begin failure aborts the Run after closing the sinks
// that were already begun successfully. End and Close errors are logged;
// the last non-nil one is returned so a real bug can surface as a non-zero
// exit at the cmd layer.
func (o *Orchestrator) Run(ctx context.Context, cfg ScanConfig) error {
	session := NewSession()
	summary := &ScanSummary{KindCounts: map[Kind]uint64{}}

	begun, err := o.beginAll(ctx, session)
	if err != nil {
		// Cleanup: close only the sinks that completed Begin successfully,
		// in reverse (LIFO) order. We deliberately do not call End — Begin
		// failed, so there is no scan to summarise.
		o.closeBegun(ctx, begun)
		return err
	}

	scanErr := o.runScanners(ctx, cfg, summary)

	finishErr := o.finishAll(ctx, summary)
	if finishErr != nil {
		return finishErr
	}
	return scanErr
}

// beginAll calls Begin on every sink, returning the prefix of sinks that
// succeeded (so a Begin failure can trigger targeted cleanup) and the first
// Begin error encountered.
func (o *Orchestrator) beginAll(ctx context.Context, session *Session) ([]Sink, error) {
	begun := make([]Sink, 0, len(o.sinks))
	for _, sink := range o.sinks {
		if err := sink.Begin(ctx, session); err != nil {
			return begun, fmt.Errorf("sink begin: %w", err)
		}
		begun = append(begun, sink)
	}
	return begun, nil
}

// closeBegun closes the given sinks in reverse order, swallowing errors;
// this is a Begin-failure cleanup path so we have no useful place to report
// errors beyond the log.
func (o *Orchestrator) closeBegun(ctx context.Context, begun []Sink) {
	for i := len(begun) - 1; i >= 0; i-- {
		if err := begun[i].Close(ctx); err != nil {
			logger.Warnf("inventory: sink close during Begin-failure cleanup: %v", err)
		}
	}
}

// runScanners drives every scanner serially, fanning each emitted item to
// every sink. Errors are captured into the summary; the loop short-circuits
// on context cancellation and returns ctx.Err() so the caller can propagate
// it (after End/Close still run for cleanup).
func (o *Orchestrator) runScanners(ctx context.Context, cfg ScanConfig, summary *ScanSummary) error {
	for _, scanner := range o.scanners {
		if err := ctx.Err(); err != nil {
			summary.Errors = append(summary.Errors, ScanError{
				ScannerName: scanner.Name(),
				ErrorType:   "context_cancelled",
				Message:     err.Error(),
			})
			return err
		}
		o.runScanner(ctx, scanner, cfg, summary)
	}
	return ctx.Err()
}

// runScanner executes a single scanner and records any failure into the
// summary. The emit closure increments counts and fans to every sink. Sink
// Emit errors are attributed to the active scanner — that is the
// "discoverer" the proto's ScanError field models.
func (o *Orchestrator) runScanner(ctx context.Context, scanner Scanner, cfg ScanConfig, summary *ScanSummary) {
	scannerName := scanner.Name()
	emit := func(item *Item) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		summary.TotalObserved++
		summary.KindCounts[item.Kind]++
		for _, sink := range o.sinks {
			if err := sink.Emit(ctx, item); err != nil {
				logger.Warnf("inventory: sink emit failed (scanner=%s): %v", scannerName, err)
				summary.Errors = append(summary.Errors, ScanError{
					ScannerName: scannerName,
					ErrorType:   "sink_emit_failed",
					Message:     err.Error(),
				})
			}
		}
		return nil
	}

	if err := scanner.Scan(ctx, cfg, emit); err != nil {
		logger.Warnf("inventory: scanner %s failed: %v", scannerName, err)
		summary.Errors = append(summary.Errors, ScanError{
			ScannerName: scannerName,
			ErrorType:   "scanner_failed",
			Message:     err.Error(),
		})
	}
}

// finishAll calls End then Close on every sink in registration order. It
// returns the last non-nil error observed across all calls; earlier errors
// are logged.
func (o *Orchestrator) finishAll(ctx context.Context, summary *ScanSummary) error {
	var lastErr error
	for _, sink := range o.sinks {
		if err := sink.End(ctx, summary); err != nil {
			logger.Warnf("inventory: sink end failed: %v", err)
			lastErr = err
		}
		if err := sink.Close(ctx); err != nil {
			logger.Warnf("inventory: sink close failed: %v", err)
			lastErr = err
		}
	}
	return lastErr
}
