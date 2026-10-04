package enrichers

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/safedep/vet/v2/internal/plugins/enrichers/insights"
	"github.com/safedep/vet/v2/internal/plugins/enrichers/malysis"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/test/acceptance/stub"
)

func startStub(t *testing.T) *stub.Server {
	t.Helper()
	s, err := stub.Start(filepath.Join("..", "..", "..", "test", "acceptance", "stub", "fixtures"))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}

func build(t *testing.T, s *stub.Server) map[string]plugin.Enricher {
	t.Helper()
	set, err := Build(Options{CommunityURL: s.URL(), APIURL: s.URL(), Workers: 4, TTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, set.Close()) })
	out := map[string]plugin.Enricher{}
	for _, sp := range set.Specs {
		out[sp.Name] = sp.Plugin
	}
	return out
}

func npm(name, version string) *model.Package {
	return &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, name, version)}
}

func TestInsights(t *testing.T) {
	s := startStub(t)
	en := build(t, s)[insights.Name]
	pad, unknown := npm("left-pad", "1.3.0"), npm("nope", "1.0.0")
	plugintest.TestEnricher(t, en, []*model.Package{pad, unknown})

	require.NotNil(t, pad.Insight)
	in := pad.Insight
	assert.Equal(t, []string{"WTFPL"}, in.Licenses)
	assert.True(t, in.Deprecated)
	assert.Equal(t, int64(1000), in.Downloads)
	assert.Equal(t, "1.3.0", in.LatestVersion)
	assert.Equal(t, "https://github.com/stevemao/left-pad", in.SourceRepo)
	require.NotNil(t, in.PublishedAt)
	assert.Equal(t, 2018, in.PublishedAt.Year())
	require.NotNil(t, in.Scorecard)
	assert.InDelta(t, 3.5, in.Scorecard.Score, 0.01)
	assert.Contains(t, in.Scorecard.Checks, "Maintained")
	require.Len(t, in.Vulnerabilities, 1)
	v := in.Vulnerabilities[0]
	assert.Equal(t, "GHSA-stub-0001", v.ID)
	assert.Equal(t, []string{"CVE-2026-0001"}, v.Aliases)
	assert.Equal(t, "high", v.Severity)
	assert.InDelta(t, 7.5, v.CVSS, 0.01)

	assert.Nil(t, unknown.Insight, "an unknown package has no data")
	assert.Equal(t, 2, s.Calls(stub.Insights))
}

func TestMalysis(t *testing.T) {
	s := startStub(t)
	en := build(t, s)[malysis.Name]
	cases := []struct {
		pkg           *model.Package
		malicious     bool
		verified      bool
		confidence    string
		wantReportURL string
	}{
		{pkg: npm("safedep-test-pkg", "0.1.3"), malicious: true, verified: true, confidence: "high", wantReportURL: malysis.ReportURL + "stub-malicious"},
		{pkg: npm("stub-suspicious", "1.0.0"), malicious: true, confidence: "medium", wantReportURL: malysis.ReportURL + "stub-suspicious"},
		{pkg: npm("stub-verified-safe", "1.0.0"), verified: true, confidence: "medium", wantReportURL: malysis.ReportURL + "stub-verified-safe"},
		{pkg: npm("lodash", "4.17.21")},
	}
	pkgs := make([]*model.Package, 0, len(cases))
	for _, tc := range cases {
		pkgs = append(pkgs, tc.pkg)
	}
	plugintest.TestEnricher(t, en, pkgs)

	for _, tc := range cases {
		t.Run(tc.pkg.ID.String(), func(t *testing.T) {
			a := tc.pkg.Malware
			require.NotNil(t, a)
			assert.Equal(t, tc.malicious, a.Malicious)
			assert.Equal(t, tc.verified, a.Verified, "only a verification record verifies the verdict")
			if tc.wantReportURL != "" {
				assert.Equal(t, tc.confidence, a.Confidence)
				assert.Equal(t, tc.wantReportURL, a.ReportURL)
			}
		})
	}
}

func TestFailOpen(t *testing.T) {
	cases := []struct {
		name string
		code codes.Code
		want error
	}{
		{name: "unavailable", code: codes.Unavailable, want: plugin.ErrUnavailable},
		{name: "deadline", code: codes.DeadlineExceeded, want: plugin.ErrUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := startStub(t)
			s.Fail(stub.Insights, tc.code)
			err := build(t, s)[insights.Name].Enrich(context.Background(), []*model.Package{npm("left-pad", "1.3.0")})
			assert.ErrorIs(t, err, tc.want)
		})
	}

	s := startStub(t)
	s.Fail(stub.Malysis, codes.PermissionDenied)
	err := build(t, s)[malysis.Name].Enrich(context.Background(), []*model.Package{npm("left-pad", "1.3.0")})
	require.Error(t, err)
	assert.NotErrorIs(t, err, plugin.ErrUnavailable, "a denied call is an error, not an outage")
}

func TestPubHasNoEnrichment(t *testing.T) {
	s := startStub(t)
	p := &model.Package{ID: model.MustPackageVersion(model.EcosystemPub, "http", "1.0.0")}
	require.NoError(t, build(t, s)[insights.Name].Enrich(context.Background(), []*model.Package{p}))
	assert.Nil(t, p.Insight)
	assert.Zero(t, s.Calls(stub.Insights))
}

func TestProbe(t *testing.T) {
	s := startStub(t)
	set, err := Build(Options{CommunityURL: s.URL(), APIURL: s.URL(), Workers: 1, TTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, set.Close()) })
	for name, err := range set.Probe(context.Background()) {
		assert.NoError(t, err, name)
	}
	s.Fail(stub.Insights, codes.Unavailable)
	got := set.Probe(context.Background())
	assert.ErrorIs(t, got[insights.Name], plugin.ErrUnavailable)
	assert.NoError(t, got[malysis.Name])
}

func TestThreatIntelCachesLessThanInsights(t *testing.T) {
	s := startStub(t)
	cases := []struct {
		name        string
		ttl         time.Duration
		threatIntel time.Duration
	}{
		{"the default ttl", 24 * time.Hour, malysis.MaxTTL},
		{"a short ttl", time.Hour, time.Hour},
		{"no cache", 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set, err := Build(Options{CommunityURL: s.URL(), APIURL: s.URL(), Workers: 1, TTL: tc.ttl})
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, set.Close()) })
			specs := map[string]Spec{}
			for _, sp := range set.Specs {
				specs[sp.Name] = sp
			}
			assert.Equal(t, tc.ttl, specs[insights.Name].TTL)
			assert.False(t, specs[insights.Name].SkipEmpty, "a package with no insight stays cached")
			assert.Equal(t, tc.threatIntel, specs[malysis.Name].TTL)
			assert.True(t, specs[malysis.Name].SkipEmpty, "a missing verdict is not cached")
		})
	}
}
