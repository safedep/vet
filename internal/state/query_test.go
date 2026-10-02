package state

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

func seed(t *testing.T) (*Scan, *model.Manifest) {
	t.Helper()
	ctx := context.Background()
	s := openStore(t)
	scan, _ := newScan(t, s, "/repo")
	m := lockfile()
	m.Packages[1].Change = model.ChangeAdded
	require.NoError(t, scan.AddManifest(ctx, "", m))

	py := &model.Manifest{
		ID: "m2", Path: "requirements.txt", Ecosystem: model.EcosystemPyPI, Kind: model.ManifestKindManifest,
		Packages: []*model.Package{{ID: model.PackageID{Ecosystem: model.EcosystemPyPI, Name: "flask", Version: "3.0.0"}, Direct: true}},
	}
	require.NoError(t, scan.AddManifest(ctx, "", py))
	return scan, m
}

func TestManifestRoundTrip(t *testing.T) {
	ctx := context.Background()
	scan, m := seed(t)

	got, err := scan.Manifest(ctx, "m1")
	require.NoError(t, err)
	assert.Equal(t, m.Path, got.Path)
	require.Len(t, got.Packages, 2)
	assert.Equal(t, m.Packages[0].ID, got.Packages[0].ID)
	assert.True(t, got.Packages[0].Direct)
	assert.Equal(t, 3, got.Packages[0].Line)
	require.NotNil(t, got.Graph)
	assert.Equal(t, []model.PackageID{m.Packages[0].ID}, got.Graph.Roots())
	assert.Equal(t, []model.PackageID{m.Packages[1].ID}, got.Graph.Children(m.Packages[0].ID))

	py, err := scan.Manifest(ctx, "m2")
	require.NoError(t, err)
	assert.Nil(t, py.Graph, "a manifest with no edges has no graph")

	var ids []string
	for mm, err := range scan.Manifests(ctx) {
		require.NoError(t, err)
		ids = append(ids, mm.ID)
	}
	assert.Equal(t, []string{"m1", "m2"}, ids)
}

func TestPackagesQuery(t *testing.T) {
	ctx := context.Background()
	scan, m := seed(t)

	count := func(q plugin.PackageQuery) int {
		n := 0
		for _, err := range scan.Packages(ctx, q) {
			require.NoError(t, err)
			n++
		}
		return n
	}
	assert.Equal(t, 3, count(plugin.PackageQuery{}))
	assert.Equal(t, 2, count(plugin.PackageQuery{ManifestID: "m1"}))
	assert.Equal(t, 1, count(plugin.PackageQuery{Ecosystem: model.EcosystemPyPI}))
	assert.Equal(t, 1, count(plugin.PackageQuery{ChangedOnly: true}))

	m.Packages[1].Insight = &model.Insight{Licenses: []string{"MIT"}}
	require.NoError(t, scan.SaveEnrichments(ctx, []EnrichmentResult{{Package: m.Packages[1], Enricher: "insights", Status: "ok"}}))
	p, err := scan.Package(ctx, m.Packages[1].ID)
	require.NoError(t, err)
	require.NotNil(t, p.Insight)
	assert.Equal(t, []string{"MIT"}, p.Insight.Licenses)

	_, err = scan.Package(ctx, model.PackageID{Ecosystem: model.EcosystemNpm, Name: "none", Version: "1"})
	assert.ErrorIs(t, err, ErrNotFound)

	var deps []string
	for d, err := range scan.Dependents(ctx, m.Packages[1].ID) {
		require.NoError(t, err)
		deps = append(deps, d.ID.Name)
	}
	assert.Equal(t, []string{"a"}, deps)

	var lacking []string
	for p, err := range scan.PackagesLacking(ctx, "insights") {
		require.NoError(t, err)
		lacking = append(lacking, p.ID.Name)
	}
	assert.Equal(t, []string{"a", "flask"}, lacking)
}

func TestFindingsQueryOrder(t *testing.T) {
	ctx := context.Background()
	scan, m := seed(t)

	mk := func(control string, sev finding.Severity, p *model.Package) finding.Finding {
		return finding.ForPackage(finding.Meta{ControlID: control, Family: finding.FamilyHygiene, Severity: sev, Title: "t"}, m.Path, p, finding.Key{})
	}
	low := mk("z-low", finding.SeverityLow, m.Packages[0])
	crit := mk("a-crit", finding.SeverityCritical, m.Packages[1])
	sup := mk("m-sup", finding.SeverityHigh, m.Packages[0])
	sup.Suppression = &finding.Suppression{Reason: "ok"}
	require.NoError(t, scan.AddFindings(ctx, m.ID, []finding.Finding{low, crit, sup}))

	var got []string
	for f, err := range scan.Findings(ctx, plugin.FindingQuery{}) {
		require.NoError(t, err)
		got = append(got, f.ControlID)
	}
	assert.Equal(t, []string{"a-crit", "z-low"}, got)

	got = nil
	for f, err := range scan.Findings(ctx, plugin.FindingQuery{IncludeSuppressed: true, MinSeverity: finding.SeverityHigh}) {
		require.NoError(t, err)
		got = append(got, f.ControlID)
	}
	assert.Equal(t, []string{"a-crit", "m-sup"}, got)

	mid, err := scan.FindingManifest(ctx, crit.ID)
	require.NoError(t, err)
	assert.Equal(t, "m1", mid)

	unevaluated, err := scan.UnevaluatedManifests(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"m2"}, unevaluated)
}
