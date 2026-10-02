package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/state"
)

// stopAfter cancels the scan when a stage reports done units.
type stopAfter struct {
	stage  string
	done   int
	cancel context.CancelFunc
}

func (stopAfter) Stage(string, int, int) {}

func (s stopAfter) Progress(stage string, done, _ int) {
	if stage == s.stage && done >= s.done {
		s.cancel()
	}
}

// interrupt runs a scan that a signal stops after the first enrich batch.
func interrupt(t *testing.T, f *fixture, dir string) *state.IndexEntry {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	en := &fakeEnricher{}
	o := f.options(t, dir, en)
	o.BatchSize = 1
	o.Observer = stopAfter{stage: StageEnrich, done: 1, cancel: cancel}

	res, err := Run(ctx, o)
	require.ErrorIs(t, err, app.ErrInterrupted)
	assert.Equal(t, app.ExitInterrupted, app.ExitCode(err))
	require.NotNil(t, res)
	require.NoError(t, res.Scan.Close())
	assert.Equal(t, 1, en.seen)
	return res.Entry
}

func TestInterruptSavesProgress(t *testing.T) {
	f := newFixture(t)
	entry := interrupt(t, f, project(t))

	got, err := f.store.Index().Get(context.Background(), entry.ID)
	require.NoError(t, err)
	assert.Equal(t, state.StatusInterrupted, got.Status)
	assert.Positive(t, got.RunTime)

	scan, err := f.store.OpenScan(context.Background(), got)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, scan.Close()) })
	assert.Nil(t, scan.Trailer(), "a stopped scan has no trailer")
	left, err := scan.PackagesToEnrich(context.Background(), "fake", "", 10)
	require.NoError(t, err)
	assert.Len(t, left, 3, "the first batch is saved")
	stage, err := scan.Stage(context.Background(), StageExtract)
	require.NoError(t, err)
	assert.Equal(t, "done", stage)
}
