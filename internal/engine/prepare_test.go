package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

// indexEnricher stands for the code usage enricher: a slow load that needs
// no package, and an Enrich that waits for it.
type indexEnricher struct {
	delay   time.Duration
	started chan struct{}
	once    sync.Once
	err     error
	// exited closes when the load returns.
	exited chan struct{}
}

func newIndexEnricher(delay time.Duration) *indexEnricher {
	return &indexEnricher{delay: delay, started: make(chan struct{}), exited: make(chan struct{})}
}

func (e *indexEnricher) load(ctx context.Context) error {
	e.once.Do(func() {
		defer close(e.exited)
		close(e.started)
		select {
		case <-time.After(e.delay):
		case <-ctx.Done():
			e.err = ctx.Err()
		}
	})
	return e.err
}

func (e *indexEnricher) Prepare(ctx context.Context) error { return e.load(ctx) }

func (e *indexEnricher) Enrich(ctx context.Context, pkgs []*model.Package) error {
	if err := e.load(ctx); err != nil {
		return err
	}
	for _, p := range pkgs {
		p.Usage = &model.Usage{Imported: p.ID.RawName() == "evil", Files: []string{"index.js"}}
	}
	return nil
}

// noPrepare hides Prepare, so the engine loads the index in Enrich.
type noPrepare struct{ e *indexEnricher }

func (n noPrepare) Enrich(ctx context.Context, pkgs []*model.Package) error {
	return n.e.Enrich(ctx, pkgs)
}

var _ plugin.Preparer = (*indexEnricher)(nil)

func preparedScan(t *testing.T, network *fakeEnricher, index plugin.Enricher) Options {
	t.Helper()
	f := newFixture(t)
	o := f.options(t, project(t), network, Control{ID: "test-name", Plugin: nameControl{name: "evil"}})
	o.Enrichers = append(o.Enrichers, Enricher{Name: "code", Version: "1", Plugin: index, Local: true})
	return o
}

func TestPrepareRunsWithTheNetworkEnrichers(t *testing.T) {
	const delay = 400 * time.Millisecond
	o := preparedScan(t, &fakeEnricher{delay: delay}, newIndexEnricher(delay))
	o.BatchSize = 100
	start := time.Now()
	runScan(t, o)
	assert.Less(t, time.Since(start), 2*delay*4/5, "the scan takes about the larger time, not the sum")
}

func TestCanceledScanStopsPrepare(t *testing.T) {
	index := newIndexEnricher(time.Hour)
	o := preparedScan(t, &fakeEnricher{delay: time.Hour}, index)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-index.started:
		case <-time.After(5 * time.Second):
		}
		cancel()
	}()
	res, err := Run(ctx, o)
	require.Error(t, err)
	if res != nil && res.Scan != nil {
		assert.NoError(t, res.Scan.Close())
	}
	select {
	case <-index.exited:
	default:
		t.Fatal("Prepare still runs after Run returned")
	}
}

func TestPrepareKeepsTheReport(t *testing.T) {
	evidence := func(index plugin.Enricher) []finding.Evidence {
		res := runScan(t, preparedScan(t, &fakeEnricher{}, index))
		var out []finding.Evidence
		for fd, err := range res.Scan.Findings(context.Background(), plugin.FindingQuery{}) {
			require.NoError(t, err)
			out = append(out, fd.Evidence...)
		}
		return out
	}
	with := evidence(newIndexEnricher(0))
	without := evidence(noPrepare{newIndexEnricher(0)})
	require.NotEmpty(t, with)
	assert.Equal(t, without, with)
}
