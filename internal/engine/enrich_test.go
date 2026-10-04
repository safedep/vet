package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

func TestEnrichBatchSkipsUncheckable(t *testing.T) {
	id := func(version string) model.PackageVersion {
		return model.MustPackageVersion(model.EcosystemPyPI, "pkg-"+version, version)
	}
	pkgs := []*model.Package{{ID: id("1.0.0")}, {ID: id("")}, {ID: id("2.0.0"), Local: true}}
	cases := []struct {
		name  string
		local bool
		want  int
	}{
		{"a registry enricher gets the versioned registry package", false, 1},
		{"a local enricher gets every package", true, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			en := &fakeEnricher{}
			r := &run{diags: &diagnostics{}}
			res, err := r.enrichBatch(context.Background(), Enricher{Name: "fake", Plugin: en, Local: tc.local}, pkgs)
			require.NoError(t, err)
			assert.Len(t, res, len(pkgs), "each package gets a result")
			assert.Equal(t, tc.want, en.seen)
		})
	}
}

// tagEnricher sets one data field of each package to a tag.
type tagEnricher struct {
	tag     string
	malware bool
}

func (e tagEnricher) Enrich(_ context.Context, pkgs []*model.Package) error {
	for _, p := range pkgs {
		if e.malware {
			p.Malware = &model.MalwareAnalysis{Summary: e.tag}
			continue
		}
		p.Insight = &model.Insight{LatestVersion: e.tag}
	}
	return nil
}

func TestCacheKeepsOnlyTheEnricherData(t *testing.T) {
	f := newFixture(t)
	dir := project(t)
	opts := func(insightsVersion, tag string) Options {
		o := f.options(t, dir, nil)
		o.Enrichers = []Enricher{
			{Name: "insights", Version: insightsVersion, TTL: time.Hour, Plugin: tagEnricher{tag: tag}},
			{Name: "malysis", Version: "1", TTL: time.Hour, Plugin: tagEnricher{tag: "verdict", malware: true}},
		}
		o.Fresh = true
		return o
	}
	runScan(t, opts("1", "old"))
	res := runScan(t, opts("2", "new"))

	for p, err := range res.Scan.Packages(context.Background(), plugin.PackageQuery{}) {
		require.NoError(t, err)
		require.NotNil(t, p.Insight, p.ID.String())
		assert.Equal(t, "new", p.Insight.LatestVersion, "a malysis cache hit does not put back the old insight of %s", p.ID)
		require.NotNil(t, p.Malware, p.ID.String())
		assert.Equal(t, "verdict", p.Malware.Summary)
	}
}

// countEnricher counts its calls and sets no data, as a backend that has
// no result yet.
type countEnricher struct{ calls *atomic.Int32 }

func (e countEnricher) Enrich(_ context.Context, pkgs []*model.Package) error {
	e.calls.Add(int32(len(pkgs)))
	return nil
}

func TestCacheSkipsEmptyResultsOnlyWhenAsked(t *testing.T) {
	f := newFixture(t)
	dir := project(t)
	for _, tc := range []struct {
		name      string
		skipEmpty bool
		secondRun bool
	}{
		{"an empty insight stays cached", false, false},
		{"an empty verdict asks again", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := &atomic.Int32{}
			opts := func() Options {
				o := f.options(t, dir, nil)
				o.Enrichers = []Enricher{{Name: tc.name, Version: "1", TTL: time.Hour, SkipEmpty: tc.skipEmpty, Plugin: countEnricher{calls}}}
				o.Fresh = true
				return o
			}
			runScan(t, opts())
			first := calls.Load()
			require.Positive(t, first)
			runScan(t, opts())
			if tc.secondRun {
				assert.Equal(t, 2*first, calls.Load(), "the second scan asks for each package again")
			} else {
				assert.Equal(t, first, calls.Load(), "the second scan reads the cache")
			}
		})
	}
}

// progressLog records the progress of the enrich stage.
type progressLog struct {
	mu     sync.Mutex
	events [][2]int
}

func (*progressLog) Stage(string, int, int) {}

func (l *progressLog) Progress(stage string, done, total int) {
	if stage != StageEnrich {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, [2]int{done, total})
}

func TestEnrichProgressCountsPackages(t *testing.T) {
	cases := []struct {
		name      string
		enrichers int
		resumed   bool
		first     [2]int
	}{
		{name: "one enricher", enrichers: 1, first: [2]int{0, 4}},
		{name: "two enrichers", enrichers: 2, first: [2]int{0, 4}},
		{name: "continued scan", enrichers: 1, resumed: true, first: [2]int{1, 3}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			dir := project(t)
			if tc.resumed {
				interrupt(t, f, dir)
				require.NoError(t, os.Remove(filepath.Join(dir, "vendor", "requirements.txt")))
			}
			o := f.options(t, dir, &fakeEnricher{})
			o.Cache, o.BatchSize = nil, 1
			for i := 1; i < tc.enrichers; i++ {
				o.Enrichers = append(o.Enrichers, Enricher{Name: fmt.Sprintf("fake%d", i), Version: "1", Plugin: &fakeEnricher{}})
			}
			log := &progressLog{}
			o.Observer = log
			runScan(t, o)

			require.NotEmpty(t, log.events)
			assert.Equal(t, tc.first, log.events[0])
			last := log.events[len(log.events)-1]
			assert.Equal(t, [2]int{tc.first[1], tc.first[1]}, last, "the stage ends with every package done")
			for i := 1; i < len(log.events); i++ {
				assert.GreaterOrEqual(t, log.events[i][0], log.events[i-1][0], "the count does not go back")
			}
		})
	}
}
