package cloud

import (
	"context"
	"errors"
	"fmt"
	"time"

	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/safedep/dry/cloud/endpointsync"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/inventory"
)

// defaultDrainTimeout bounds how long Close blocks waiting for the
// endpointsync flusher to ship pending events.
const defaultDrainTimeout = 30 * time.Second

// syncClient is the narrow surface CloudSink depends on. The real
// *endpointsync.syncClient satisfies it; tests stub it.
type syncClient interface {
	NewEvent() (*servicev1.ToolEvent, error)
	Emit(ctx context.Context, ev *servicev1.ToolEvent) error
	Sync(ctx context.Context) (int, error)
	Close() error
}

// Option configures a CloudSink at construction.
type Option func(*CloudSink)

// WithDrainTimeout overrides the bound applied to the endpointsync
// flusher drain on Close. Values <= 0 are ignored (the default
// applies).
func WithDrainTimeout(d time.Duration) Option {
	return func(s *CloudSink) {
		if d > 0 {
			s.drainTimeout = d
		}
	}
}

// CloudSink is an inventory.Sink that translates each emitted item,
// the end-of-scan summary, and per-discoverer errors into a
// VetInventoryEvent inside a ToolEvent envelope, then hands the
// envelope to endpointsync for durable WAL-backed delivery to
// SafeDep Cloud.
//
// CloudSink is not safe for concurrent use; the inventory
// orchestrator drives sinks serially. The sink holds no goroutines
// of its own — concurrency between the producer (inventory pipeline)
// and the consumer (cloud delivery) lives inside endpointsync.
//
// Failures fall into two buckets:
//   - endpointsync.ErrWALFull on Emit: log and drop. The orchestrator
//     should not abort a scan because the local buffer is saturated.
//   - any other error from NewEvent or Emit: log and continue. Emit
//     returns nil so the orchestrator's summary records each failure
//     once via its own sink_emit_failed channel.
type CloudSink struct {
	client       syncClient
	drainTimeout time.Duration
	session      *inventory.Session
}

// New constructs a CloudSink wired to the given endpointsync client.
// The cmd layer constructs and owns the underlying client; CloudSink
// only consumes the narrow syncClient interface so the package stays
// independent of credential resolution and gRPC wiring.
func New(client syncClient, opts ...Option) *CloudSink {
	s := &CloudSink{
		client:       client,
		drainTimeout: defaultDrainTimeout,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Begin captures the session so subsequent Emit/End calls can attach
// invocation_id to every emitted ToolEvent. Returns no error: a
// CloudSink with a real client cannot fail to start.
func (s *CloudSink) Begin(_ context.Context, session *inventory.Session) error {
	s.session = session
	return nil
}

// Emit translates one item into an ITEM_OBSERVED VetInventoryEvent and
// hands it to endpointsync. Always returns nil; transient delivery
// failures are logged and dropped so the scan does not abort on
// cloud-side problems.
func (s *CloudSink) Emit(ctx context.Context, item *inventory.Item) error {
	s.send(ctx, itemToVetEvent(item), "item_observed")
	return nil
}

// End emits one SCAN_SUMMARY event followed by one ERROR event per
// recorded ScanError. Failures of any single emission do not prevent
// the others from being attempted.
func (s *CloudSink) End(ctx context.Context, summary *inventory.ScanSummary) error {
	s.send(ctx, summaryToVetEvent(summary), "scan_summary")
	for _, e := range summary.Errors {
		s.send(ctx, scanErrorToVetEvent(e), "scan_error")
	}
	return nil
}

// Close drains the endpointsync WAL within the configured deadline and
// then closes the underlying client. Drain failures (including
// timeouts) are logged and swallowed — undelivered events stay in the
// WAL and ship on the next run, per the ADR's grace-bound contract.
// Client.Close errors propagate so a real bug surfaces as a non-zero
// exit at the cmd layer.
func (s *CloudSink) Close(ctx context.Context) error {
	drainCtx, cancel := context.WithTimeout(ctx, s.drainTimeout)
	defer cancel()

	if n, err := s.client.Sync(drainCtx); err != nil {
		logger.Warnf("cloud sink: drain incomplete (synced=%d, timeout=%s): %v",
			n, s.drainTimeout, err)
	} else {
		logger.Debugf("cloud sink: drained %d event(s) on close", n)
	}

	if err := s.client.Close(); err != nil {
		return fmt.Errorf("cloud sink: close: %w", err)
	}
	return nil
}

// send is the common build-and-emit path used by Emit and End. It
// builds the ToolEvent envelope, attaches invocation_id and the vet
// payload, and emits via the client. WAL-full is logged and dropped;
// other errors are logged. The kind argument is a coarse classifier
// used in log messages so failures from item vs summary vs error
// emissions are distinguishable in operator-facing logs.
func (s *CloudSink) send(ctx context.Context, vetEvent *controltowerv1pb.VetInventoryEvent, kind string) {
	toolEvent, err := s.client.NewEvent()
	if err != nil {
		logger.Warnf("cloud sink: new event (%s): %v", kind, err)
		return
	}
	toolEvent.SetVetEvent(vetEvent)
	if s.session != nil {
		toolEvent.SetInvocationId(s.session.InvocationID)
	}
	if err := s.client.Emit(ctx, toolEvent); err != nil {
		if errors.Is(err, endpointsync.ErrWALFull) {
			logger.Warnf("cloud sink: WAL full, dropping %s event: %v", kind, err)
			return
		}
		logger.Warnf("cloud sink: emit %s event: %v", kind, err)
	}
}
