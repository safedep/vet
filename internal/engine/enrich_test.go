package engine

import (
	"context"
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
