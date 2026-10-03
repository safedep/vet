package engine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

func TestEnrichBatchSkipsUncheckable(t *testing.T) {
	id := func(version string) model.PackageID {
		return model.PackageID{Ecosystem: model.EcosystemPyPI, Name: "pkg-" + version, Version: version}
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
