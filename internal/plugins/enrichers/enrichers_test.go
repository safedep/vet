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
	return &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: name, Version: version}}
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
	evil, clean := npm("safedep-test-pkg", "0.1.3"), npm("lodash", "4.17.21")
	plugintest.TestEnricher(t, en, []*model.Package{evil, clean})

	require.NotNil(t, evil.Malware)
	assert.True(t, evil.Malware.Malicious)
	assert.Equal(t, "high", evil.Malware.Confidence)
	assert.Equal(t, malysis.ReportURL+"stub-malicious", evil.Malware.ReportURL)
	require.NotNil(t, clean.Malware)
	assert.False(t, clean.Malware.Malicious)
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
	p := &model.Package{ID: model.PackageID{Ecosystem: model.EcosystemPub, Name: "http", Version: "1.0.0"}}
	require.NoError(t, build(t, s)[insights.Name].Enrich(context.Background(), []*model.Package{p}))
	assert.Nil(t, p.Insight)
	assert.Zero(t, s.Calls(stub.Insights))
}
