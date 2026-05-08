package inventory

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Session is created once per Orchestrator.Run and propagates the scan's
// invocation identity through every sink.
type Session struct {
	// InvocationID is a UUID identifying this scan run. Equal across all
	// events emitted by the same Run; distinct between Runs.
	InvocationID string
	// StartedAt is the wall-clock time the session was created.
	StartedAt time.Time
}

// NewSession constructs a Session with a freshly generated UUID
// invocation_id and a now() timestamp.
func NewSession() *Session {
	return &Session{
		InvocationID: uuid.New().String(),
		StartedAt:    time.Now(),
	}
}

// ScanError describes a discoverer-level failure recorded during a scan.
// Field set mirrors proto VetInventoryEvent.ScanError, with ScannerName
// substituted for the proto's Discoverer field.
type ScanError struct {
	// ScannerName is the Scanner.Name() of the active scanner. Sink.Emit
	// failures are attributed here too, matching the proto's discoverer
	// field semantics.
	ScannerName string
	// ErrorType is a coarse classifier (e.g. "scanner_failed",
	// "sink_emit_failed"). Optional; empty when not classified.
	ErrorType string
	// Message is the human-readable failure description.
	Message string
}

// ScanSummary aggregates the result of a scan. Built by the orchestrator and
// passed to Sink.End. The orchestrator owns its lifecycle; sinks must treat
// the value as read-only.
type ScanSummary struct {
	// TotalObserved is the number of items emitted across all scanners.
	TotalObserved uint64
	// KindCounts is the per-Kind tally of emitted items.
	KindCounts map[Kind]uint64
	// Errors are the discoverer-level failures collected during the scan;
	// the scan continues past each error.
	Errors []ScanError
}

// Sink consumes the producer pipeline. Sinks are NOT required to be
// thread-safe: the orchestrator drives them serially.
//
// Lifecycle, exactly once per Orchestrator.Run:
//
//	Begin -> Emit* -> End -> Close
//
// Begin failure aborts the Run. Emit failure does not: the orchestrator
// records the error in ScanSummary.Errors and continues with the remaining
// sinks and scanners. End and Close errors are logged; only the last
// non-nil error from End/Close propagates out of Run, so a real bug surfaces
// as a non-zero exit.
type Sink interface {
	// Begin announces a new scan. Returning an error aborts the Run.
	Begin(ctx context.Context, session *Session) error
	// Emit consumes one observed item. The orchestrator does not retry; an
	// error is captured into the ScanSummary and the next sink is called.
	Emit(ctx context.Context, item *Item) error
	// End delivers the aggregated summary at end-of-scan.
	End(ctx context.Context, summary *ScanSummary) error
	// Close releases resources held by the sink.
	Close(ctx context.Context) error
}
