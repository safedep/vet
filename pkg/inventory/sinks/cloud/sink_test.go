package cloud

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	servicev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/google/uuid"
	"github.com/safedep/dry/cloud/endpointsync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/safedep/vet/pkg/inventory"
)

// fakeSyncClient is a programmable stub for the SyncClient interface.
// Each method records calls (and arguments where useful) so tests can
// assert against real behaviour without needing a live SQLite-backed
// WAL. Functions that callers need to script per-test (Emit response,
// Sync behaviour) are exposed as fields so each test wires only what
// it cares about; everything else has a sensible default.
type fakeSyncClient struct {
	mu sync.Mutex

	emittedEvents []*servicev1.ToolEvent
	emitErr       error // returned by Emit; static across calls

	syncFn       func(ctx context.Context) (int, error)
	syncCount    int
	syncLastSeen context.Context

	closeErr   error
	closeCount int

	newEventErr error
}

func newFakeSyncClient() *fakeSyncClient { return &fakeSyncClient{} }

func (f *fakeSyncClient) NewEvent() (*servicev1.ToolEvent, error) {
	if f.newEventErr != nil {
		return nil, f.newEventErr
	}
	return newToolEventSkeleton(), nil
}

// newToolEventSkeleton returns a fresh ToolEvent matching the real
// endpointsync surface (event_id / tool_name / tool_version /
// timestamp pre-filled). Kept as a free function so the fake stays
// trivially small.
func newToolEventSkeleton() *servicev1.ToolEvent {
	return servicev1.ToolEvent_builder{
		EventId:     uuid.New().String(),
		ToolName:    "vet",
		ToolVersion: "test",
		Timestamp:   timestamppb.Now(),
	}.Build()
}

func (f *fakeSyncClient) Emit(_ context.Context, ev *servicev1.ToolEvent) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.emittedEvents = append(f.emittedEvents, ev)
	return f.emitErr
}

func (f *fakeSyncClient) Sync(ctx context.Context) (int, error) {
	f.mu.Lock()
	f.syncCount++
	f.syncLastSeen = ctx
	fn := f.syncFn
	f.mu.Unlock()
	if fn != nil {
		return fn(ctx)
	}
	return 0, nil
}

func (f *fakeSyncClient) Close() error {
	f.closeCount++
	return f.closeErr
}

func (f *fakeSyncClient) emitted() []*servicev1.ToolEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*servicev1.ToolEvent, len(f.emittedEvents))
	copy(out, f.emittedEvents)
	return out
}

func sampleItem() *inventory.Item {
	return &inventory.Item{
		Kind:         inventory.KindCLITool,
		ItemIdentity: "id-1",
		SourceID:     "src-1",
		Name:         "claude",
		App:          "claude_code",
		Scope:        inventory.ScopeSystem,
		ConfigPath:   "/usr/local/bin/claude",
		Metadata:     map[string]string{"binary.path": "/usr/local/bin/claude"},
	}
}

func TestCloudSink_BeginCapturesSession(t *testing.T) {
	fake := newFakeSyncClient()
	sink := New(fake)
	session := inventory.NewSession()

	require.NoError(t, sink.Begin(context.Background(), session))
	require.NoError(t, sink.Emit(context.Background(), sampleItem()))

	events := fake.emitted()
	require.Len(t, events, 1)
	assert.Equal(t, session.InvocationID, events[0].GetInvocationId())
}

func TestCloudSink_EmitProducesItemObservedEnvelope(t *testing.T) {
	fake := newFakeSyncClient()
	sink := New(fake)
	session := inventory.NewSession()

	require.NoError(t, sink.Begin(context.Background(), session))
	require.NoError(t, sink.Emit(context.Background(), sampleItem()))

	events := fake.emitted()
	require.Len(t, events, 1)

	te := events[0]
	assert.Equal(t, session.InvocationID, te.GetInvocationId())
	require.True(t, te.HasVetEvent())

	ve := te.GetVetEvent()
	assert.Equal(t,
		controltowerv1pb.VetInventoryEventType_VET_INVENTORY_EVENT_TYPE_ITEM_OBSERVED,
		ve.GetEventType())
	require.True(t, ve.HasItemObserved())
	assert.Equal(t, "claude", ve.GetItemObserved().GetName())
}

func TestCloudSink_EndEmitsSummaryThenOneErrorPerScanError(t *testing.T) {
	fake := newFakeSyncClient()
	sink := New(fake)

	require.NoError(t, sink.Begin(context.Background(), inventory.NewSession()))
	summary := &inventory.ScanSummary{
		TotalObserved: 2,
		KindCounts:    map[inventory.Kind]uint64{inventory.KindCLITool: 2},
		Errors: []inventory.ScanError{
			{ScannerName: "a", ErrorType: "scanner_failed", Message: "x"},
			{ScannerName: "b", ErrorType: "sink_emit_failed", Message: "y"},
		},
	}

	require.NoError(t, sink.End(context.Background(), summary))

	events := fake.emitted()
	require.Len(t, events, 3)

	require.True(t, events[0].HasVetEvent())
	assert.Equal(t,
		controltowerv1pb.VetInventoryEventType_VET_INVENTORY_EVENT_TYPE_SCAN_SUMMARY,
		events[0].GetVetEvent().GetEventType())

	for i, e := range summary.Errors {
		ve := events[i+1].GetVetEvent()
		assert.Equal(t,
			controltowerv1pb.VetInventoryEventType_VET_INVENTORY_EVENT_TYPE_ERROR,
			ve.GetEventType(), "event[%d] should be ERROR", i+1)
		require.True(t, ve.HasError(), "event[%d] should have error payload", i+1)
		assert.Equal(t, e.ScannerName, ve.GetError().GetDiscoverer())
	}
}

func TestCloudSink_EmitSwallowsWALFullError(t *testing.T) {
	fake := newFakeSyncClient()
	fake.emitErr = endpointsync.ErrWALFull

	sink := New(fake)
	require.NoError(t, sink.Begin(context.Background(), inventory.NewSession()))

	// Emit must still report nil so the orchestrator does not abort.
	err := sink.Emit(context.Background(), sampleItem())
	assert.NoError(t, err)
	assert.Len(t, fake.emitted(), 1, "WAL-full event should still reach the client")
}

func TestCloudSink_EmitSwallowsGenericEmitError(t *testing.T) {
	fake := newFakeSyncClient()
	fake.emitErr = errors.New("transport blew up")

	sink := New(fake)
	require.NoError(t, sink.Begin(context.Background(), inventory.NewSession()))

	assert.NoError(t, sink.Emit(context.Background(), sampleItem()))
}

func TestCloudSink_EmitSwallowsNewEventError(t *testing.T) {
	fake := newFakeSyncClient()
	fake.newEventErr = errors.New("nope")

	sink := New(fake)
	require.NoError(t, sink.Begin(context.Background(), inventory.NewSession()))

	assert.NoError(t, sink.Emit(context.Background(), sampleItem()))
	assert.Empty(t, fake.emitted())
}

func TestCloudSink_CloseDrainsAndClosesClient(t *testing.T) {
	fake := newFakeSyncClient()
	sink := New(fake)

	require.NoError(t, sink.Close(context.Background()))
	assert.Equal(t, 1, fake.syncCount, "Close should call Sync exactly once")
	assert.Equal(t, 1, fake.closeCount, "Close should call client.Close exactly once")

	require.NotNil(t, fake.syncLastSeen, "Sync should have received a context")
	_, hasDeadline := fake.syncLastSeen.Deadline()
	assert.True(t, hasDeadline, "Close must apply WithDrainTimeout to the Sync context")
}

func TestCloudSink_CloseSwallowsSyncTimeout(t *testing.T) {
	fake := newFakeSyncClient()
	// Stub Sync respects ctx cancellation; with a 50ms drain budget it
	// will return ctx.Err() rather than ever completing.
	fake.syncFn = func(ctx context.Context) (int, error) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(5 * time.Second):
			return 0, nil
		}
	}

	sink := New(fake, WithDrainTimeout(50*time.Millisecond))
	require.NoError(t, sink.Begin(context.Background(), inventory.NewSession()))

	start := time.Now()
	err := sink.Close(context.Background())
	elapsed := time.Since(start)

	assert.NoError(t, err, "Close must swallow drain-timeout (exit 0 per ADR)")
	assert.Less(t, elapsed, 2*time.Second, "Close should respect drain timeout, not the stub's 5s")
	assert.Equal(t, 1, fake.closeCount)
}

func TestCloudSink_ClosePropagatesCloseError(t *testing.T) {
	fake := newFakeSyncClient()
	fake.closeErr = errors.New("disk failure")

	sink := New(fake)

	err := sink.Close(context.Background())
	require.Error(t, err)
	assert.ErrorContains(t, err, "disk failure")
}

func TestCloudSink_WithDrainTimeoutIgnoresNonPositive(t *testing.T) {
	fake := newFakeSyncClient()

	sink := New(fake, WithDrainTimeout(0), WithDrainTimeout(-1*time.Second))
	assert.Equal(t, defaultDrainTimeout, sink.drainTimeout,
		"non-positive drain timeouts must not override the default")
}
