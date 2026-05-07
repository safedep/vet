package inventory

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingSink captures the sequence of lifecycle calls a sink receives.
// One instance per sink; the orchestrator drives them serially so no locks
// are required.
type recordingSink struct {
	name string
	// calls records the ordered method tags this sink saw, e.g.
	// "begin", "emit:mcp_server", "end:2", "close".
	calls []string
	// invocationIDs records the InvocationID seen on each Begin call.
	invocationIDs []string
	// summaries captures the *ScanSummary passed to End.
	summaries []*ScanSummary
	// items captures pointers passed to Emit.
	items []*Item

	// Pluggable error hooks; nil means "no error".
	beginErr func() error
	emitErr  func(*Item) error
	endErr   func() error
	closeErr func() error
}

func (s *recordingSink) Begin(_ context.Context, session *Session) error {
	s.calls = append(s.calls, "begin")
	s.invocationIDs = append(s.invocationIDs, session.InvocationID)
	if s.beginErr != nil {
		return s.beginErr()
	}
	return nil
}

func (s *recordingSink) Emit(_ context.Context, item *Item) error {
	s.calls = append(s.calls, "emit:"+item.Name)
	s.items = append(s.items, item)
	if s.emitErr != nil {
		return s.emitErr(item)
	}
	return nil
}

func (s *recordingSink) End(_ context.Context, summary *ScanSummary) error {
	s.calls = append(s.calls, "end")
	s.summaries = append(s.summaries, summary)
	if s.endErr != nil {
		return s.endErr()
	}
	return nil
}

func (s *recordingSink) Close(_ context.Context) error {
	s.calls = append(s.calls, "close")
	if s.closeErr != nil {
		return s.closeErr()
	}
	return nil
}

// stubScanner emits a fixed list of items, optionally returning an error
// after exhausting them.
type stubScanner struct {
	name  string
	items []*Item
	err   error
}

func (s *stubScanner) Name() string { return s.name }

func (s *stubScanner) Scan(_ context.Context, _ ScanConfig, emit EmitFunc) error {
	for _, item := range s.items {
		if err := emit(item); err != nil {
			return err
		}
	}
	return s.err
}

func TestOrchestratorRunSingleScannerSingleSink(t *testing.T) {
	sink := &recordingSink{name: "rec"}
	scanner := &stubScanner{
		name: "stub",
		items: []*Item{
			{Kind: KindMCPServer, Name: "alpha"},
			{Kind: KindCLITool, Name: "beta"},
		},
	}
	orch := New([]Scanner{scanner}, []Sink{sink})

	err := orch.Run(context.Background(), ScanConfig{})

	require.NoError(t, err)
	assert.Equal(t, []string{"begin", "emit:alpha", "emit:beta", "end", "close"}, sink.calls)
}

func TestOrchestratorRunFansItemsToAllSinksInRegistrationOrder(t *testing.T) {
	sinkA := &recordingSink{name: "a"}
	sinkB := &recordingSink{name: "b"}
	scanner1 := &stubScanner{
		name:  "s1",
		items: []*Item{{Kind: KindMCPServer, Name: "alpha"}},
	}
	scanner2 := &stubScanner{
		name:  "s2",
		items: []*Item{{Kind: KindCLITool, Name: "beta"}},
	}
	orch := New([]Scanner{scanner1, scanner2}, []Sink{sinkA, sinkB})

	err := orch.Run(context.Background(), ScanConfig{})

	require.NoError(t, err)
	expected := []string{"begin", "emit:alpha", "emit:beta", "end", "close"}
	assert.Equal(t, expected, sinkA.calls)
	assert.Equal(t, expected, sinkB.calls)
}

func TestOrchestratorRunInvocationIDIsSharedAcrossSinks(t *testing.T) {
	sinkA := &recordingSink{name: "a"}
	sinkB := &recordingSink{name: "b"}
	scanner := &stubScanner{name: "s", items: []*Item{{Kind: KindMCPServer, Name: "x"}}}
	orch := New([]Scanner{scanner}, []Sink{sinkA, sinkB})

	require.NoError(t, orch.Run(context.Background(), ScanConfig{}))

	require.Len(t, sinkA.invocationIDs, 1)
	require.Len(t, sinkB.invocationIDs, 1)
	assert.Equal(t, sinkA.invocationIDs[0], sinkB.invocationIDs[0])
	assert.NotEmpty(t, sinkA.invocationIDs[0])
}

func TestOrchestratorRunSummaryHasCorrectCounts(t *testing.T) {
	sink := &recordingSink{name: "rec"}
	scanner := &stubScanner{
		name: "s",
		items: []*Item{
			{Kind: KindMCPServer, Name: "a"},
			{Kind: KindMCPServer, Name: "b"},
			{Kind: KindCLITool, Name: "c"},
		},
	}
	orch := New([]Scanner{scanner}, []Sink{sink})

	require.NoError(t, orch.Run(context.Background(), ScanConfig{}))

	require.Len(t, sink.summaries, 1)
	summary := sink.summaries[0]
	assert.Equal(t, uint64(3), summary.TotalObserved)
	assert.Equal(t, uint64(2), summary.KindCounts[KindMCPServer])
	assert.Equal(t, uint64(1), summary.KindCounts[KindCLITool])
	assert.Empty(t, summary.Errors)
}

func TestOrchestratorRunSinkEmitErrorDoesNotAbortScan(t *testing.T) {
	failingSink := &recordingSink{
		name: "failing",
		emitErr: func(_ *Item) error {
			return errors.New("write failed")
		},
	}
	healthySink := &recordingSink{name: "healthy"}
	scanner1 := &stubScanner{name: "s1", items: []*Item{{Kind: KindMCPServer, Name: "alpha"}}}
	scanner2 := &stubScanner{name: "s2", items: []*Item{{Kind: KindCLITool, Name: "beta"}}}
	orch := New([]Scanner{scanner1, scanner2}, []Sink{failingSink, healthySink})

	err := orch.Run(context.Background(), ScanConfig{})

	require.NoError(t, err)
	// The healthy sink saw both items, proving scan continued.
	assert.Equal(t,
		[]string{"begin", "emit:alpha", "emit:beta", "end", "close"},
		healthySink.calls)
	// The summary delivered to End records sink-Emit errors against the
	// scanner that produced the item — proto ScanError.discoverer semantics.
	require.Len(t, healthySink.summaries, 1)
	require.Len(t, healthySink.summaries[0].Errors, 2)
	assert.Equal(t, "s1", healthySink.summaries[0].Errors[0].ScannerName)
	assert.Equal(t, "s2", healthySink.summaries[0].Errors[1].ScannerName)
	for _, e := range healthySink.summaries[0].Errors {
		assert.Equal(t, "sink_emit_failed", e.ErrorType)
		assert.Contains(t, e.Message, "write failed")
	}
}

func TestOrchestratorRunScannerErrorContinuesToNextScanner(t *testing.T) {
	sink := &recordingSink{name: "rec"}
	failingScanner := &stubScanner{
		name:  "broken",
		items: []*Item{{Kind: KindMCPServer, Name: "alpha"}},
		err:   errors.New("scan exploded"),
	}
	healthyScanner := &stubScanner{
		name:  "ok",
		items: []*Item{{Kind: KindCLITool, Name: "beta"}},
	}
	orch := New([]Scanner{failingScanner, healthyScanner}, []Sink{sink})

	err := orch.Run(context.Background(), ScanConfig{})

	require.NoError(t, err)
	// Both items reached the sink: scan didn't abort.
	assert.Equal(t,
		[]string{"begin", "emit:alpha", "emit:beta", "end", "close"},
		sink.calls)
	require.Len(t, sink.summaries, 1)
	require.Len(t, sink.summaries[0].Errors, 1)
	assert.Equal(t, "broken", sink.summaries[0].Errors[0].ScannerName)
	assert.Contains(t, sink.summaries[0].Errors[0].Message, "scan exploded")
}

func TestOrchestratorRunBeginErrorAbortsAndClosesPriorSinks(t *testing.T) {
	sinkA := &recordingSink{name: "a"}
	sinkB := &recordingSink{
		name:     "b",
		beginErr: func() error { return errors.New("begin b failed") },
	}
	sinkC := &recordingSink{name: "c"}
	scanner := &stubScanner{name: "s", items: []*Item{{Kind: KindMCPServer, Name: "x"}}}
	orch := New([]Scanner{scanner}, []Sink{sinkA, sinkB, sinkC})

	err := orch.Run(context.Background(), ScanConfig{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "begin b failed")
	// SinkA had a successful Begin -> must be Closed.
	assert.Equal(t, []string{"begin", "close"}, sinkA.calls)
	// SinkB had Begin called but it failed -> NOT Closed (no resource yet).
	assert.Equal(t, []string{"begin"}, sinkB.calls)
	// SinkC never had Begin called.
	assert.Empty(t, sinkC.calls)
}

func TestOrchestratorRunEndErrorReturnsLastNonNilError(t *testing.T) {
	sinkA := &recordingSink{
		name:   "a",
		endErr: func() error { return errors.New("end a failed") },
	}
	sinkB := &recordingSink{
		name:   "b",
		endErr: func() error { return errors.New("end b failed") },
	}
	scanner := &stubScanner{name: "s", items: nil}
	orch := New([]Scanner{scanner}, []Sink{sinkA, sinkB})

	err := orch.Run(context.Background(), ScanConfig{})

	require.Error(t, err)
	// Both sinks got End and Close, regardless of errors.
	assert.Equal(t, []string{"begin", "end", "close"}, sinkA.calls)
	assert.Equal(t, []string{"begin", "end", "close"}, sinkB.calls)
	// The error returned is the LAST one observed (sinkB's End).
	assert.Contains(t, err.Error(), "end b failed")
}

func TestOrchestratorRunCloseErrorReturnedWhenLastError(t *testing.T) {
	sink := &recordingSink{
		name:     "rec",
		closeErr: func() error { return errors.New("close failed") },
	}
	scanner := &stubScanner{name: "s", items: nil}
	orch := New([]Scanner{scanner}, []Sink{sink})

	err := orch.Run(context.Background(), ScanConfig{})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "close failed")
}

func TestOrchestratorRunRespectsContextCancellationBetweenScanners(t *testing.T) {
	sink := &recordingSink{name: "rec"}
	scanner1 := &stubScanner{
		name:  "first",
		items: []*Item{{Kind: KindMCPServer, Name: "alpha"}},
	}
	// scanner2 must NOT run.
	scanner2 := &stubScanner{
		name:  "second",
		items: []*Item{{Kind: KindCLITool, Name: "beta"}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run starts.

	orch := New([]Scanner{scanner1, scanner2}, []Sink{sink})
	err := orch.Run(ctx, ScanConfig{})

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
	// End/Close still run on cleanup paths so the sink is never leaked,
	// but no items are emitted because the scan loop short-circuits.
	for _, call := range sink.calls {
		assert.NotContains(t, call, "emit:")
	}
}

func TestOrchestratorRunNoScannersStillCallsLifecycle(t *testing.T) {
	sink := &recordingSink{name: "rec"}
	orch := New(nil, []Sink{sink})

	require.NoError(t, orch.Run(context.Background(), ScanConfig{}))

	assert.Equal(t, []string{"begin", "end", "close"}, sink.calls)
	require.Len(t, sink.summaries, 1)
	assert.Equal(t, uint64(0), sink.summaries[0].TotalObserved)
}
