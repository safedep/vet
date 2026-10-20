package engine

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

func TestReachOf(t *testing.T) {
	app := model.MustPackageVersion(model.EcosystemNpm, "app-lib", "1.0.0")
	tool := model.MustPackageVersion(model.EcosystemNpm, "test-tool", "1.0.0")
	dep := model.MustPackageVersion(model.EcosystemNpm, "dep", "1.0.0")
	lone := model.MustPackageVersion(model.EcosystemNpm, "lone", "1.0.0")
	graph := model.NewGraph()
	graph.AddRoot(app)
	graph.AddRoot(tool)
	graph.AddRoot(lone)
	graph.AddEdge(app, dep)
	graph.AddEdge(tool, dep)

	site := []model.ImportSite{{File: "index.js", Line: 1}}
	cases := []struct {
		name  string
		level report.ReachLevel
		usage *model.Usage
		// appUsage and toolUsage are the usage of the two roots.
		appUsage, toolUsage *model.Usage
		noGraph             bool
		want                *finding.Reach
	}{
		{
			name: "no usage gives no reach", level: report.ReachImport,
		},
		{
			name: "an import", level: report.ReachImport,
			usage: &model.Usage{Imported: true, Imports: site},
			want:  &finding.Reach{Level: finding.ReachImported, Confidence: finding.ConfidenceHigh, Imports: site},
		},
		{
			name: "function level with no symbol data stays imported", level: report.ReachFunction,
			usage: &model.Usage{Imported: true, Imports: site},
			want:  &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachNoSymbolData, Confidence: finding.ConfidenceHigh, Imports: site},
		},
		{
			name: "function level with a symbol record names the fix sites", level: report.ReachFunction,
			usage: &model.Usage{Imported: true, Symbols: []model.SymbolRecord{
				{Advisory: "GHSA-other", FixSites: []string{"a.B"}},
				{Advisory: "GHSA-test", Record: "GO-2026-0001", Coverage: "exact", FixSites: []string{"dep.Render"}},
			}},
			want: &finding.Reach{Level: finding.ReachImported, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "an import from tests only", level: report.ReachImport,
			usage: &model.Usage{Imported: true, TestOnly: true},
			want:  &finding.Reach{Level: finding.ReachImported, Confidence: finding.ConfidenceHigh, TestOnly: true},
		},
		{
			name: "a transitive package of an imported package", level: report.ReachImport,
			usage: &model.Usage{}, appUsage: &model.Usage{Imported: true}, toolUsage: &model.Usage{Imported: true, TestOnly: true},
			want: &finding.Reach{Level: finding.ReachImported, Confidence: finding.ConfidenceMedium, Via: []string{app.PURL(), dep.PURL()}},
		},
		{
			name: "a transitive package of a test import only", level: report.ReachImport,
			usage: &model.Usage{}, appUsage: &model.Usage{}, toolUsage: &model.Usage{Imported: true, TestOnly: true},
			want: &finding.Reach{Level: finding.ReachImported, Confidence: finding.ConfidenceMedium, Via: []string{tool.PURL(), dep.PURL()}, TestOnly: true},
		},
		{
			name: "no import and no path", level: report.ReachImport,
			usage: &model.Usage{}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachUnused, Confidence: finding.ConfidenceMedium},
		},
		{
			name: "a stopped analysis is unknown", level: report.ReachImport,
			usage: &model.Usage{Incomplete: true, DynamicImport: true},
			want:  &finding.Reach{Level: finding.ReachUnknown, Cause: finding.ReachBudget, Confidence: finding.ConfidenceLow},
		},
		{
			name: "an unread file is unknown", level: report.ReachImport,
			usage: &model.Usage{UnreadFiles: true}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachUnknown, Cause: finding.ReachUnreadFiles, Confidence: finding.ConfidenceLow},
		},
		{
			name: "no parsed file of the language is unknown", level: report.ReachImport,
			usage: &model.Usage{NoSourceFiles: true}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachUnknown, Cause: finding.ReachNoSourceFiles, Confidence: finding.ConfidenceLow},
		},
		{
			name: "a computed import is unknown", level: report.ReachImport,
			usage: &model.Usage{DynamicImport: true},
			want:  &finding.Reach{Level: finding.ReachUnknown, Cause: finding.ReachDynamicImport, Confidence: finding.ConfidenceLow},
		},
		{
			name: "no graph is unknown", level: report.ReachImport, noGraph: true,
			usage: &model.Usage{},
			want:  &finding.Reach{Level: finding.ReachUnknown, Cause: finding.ReachNoGraph, Confidence: finding.ConfidenceLow},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			target := &model.Package{ID: dep, Enrichment: model.Enrichment{Usage: c.usage}}
			m := &model.Manifest{Graph: graph, Packages: []*model.Package{
				{ID: app, Enrichment: model.Enrichment{Usage: c.appUsage}},
				{ID: tool, Enrichment: model.Enrichment{Usage: c.toolUsage}},
				{ID: lone},
				target,
			}}
			if c.noGraph {
				m.Graph = nil
			}
			assert.Equal(t, c.want, reachOf(c.level, target, m, "GHSA-test"))
		})
	}
}

// sourceEnricher records the directory that the engine gives it.
type sourceEnricher struct {
	fakeEnricher
	dir   string
	bound bool
}

func (s *sourceEnricher) UseSource(dir string) { s.dir, s.bound = dir, true }

var _ plugin.SourceEnricher = (*sourceEnricher)(nil)

func TestReachOfTheScan(t *testing.T) {
	cases := []struct {
		name   string
		reach  report.ReachInfo
		target func(t *testing.T) string
		want   report.ReachInfo
		dir    bool
	}{
		{"a directory computes reach", report.ReachInfo{Level: report.ReachImport}, project, report.ReachInfo{Level: report.ReachImport, Status: report.ReachComputed}, true},
		{"a PURL has no source", report.ReachInfo{Level: report.ReachFunction}, func(*testing.T) string { return "pkg:npm/left-pad@1.3.0" }, report.ReachInfo{Level: report.ReachFunction, Status: report.ReachNoSource}, false},
		{"reach off", report.ReachInfo{}, project, report.ReachInfo{Level: report.ReachOff, Status: report.ReachNotComputed}, true},
		{"a status of the caller stays", report.ReachInfo{Level: report.ReachFunction, Status: report.ReachUnavailable}, project, report.ReachInfo{Level: report.ReachFunction, Status: report.ReachUnavailable}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			src := &sourceEnricher{}
			o := f.options(t, c.target(t), nil)
			o.Enrichers = []Enricher{{Name: "code", Version: "1", Plugin: src, Local: true}}
			o.Reach = c.reach
			res := runScan(t, o)
			require.NotNil(t, res.Scan.Header().Scan.Reach)
			assert.Equal(t, c.want, *res.Scan.Header().Scan.Reach)
			assert.True(t, src.bound, "the engine gives each source enricher its directory")
			assert.Equal(t, c.dir, src.dir != "")
		})
	}
}

func TestReachIsOnVulnerabilityFindingsOnly(t *testing.T) {
	f := newFixture(t)
	o := f.options(t, project(t), nil,
		Control{ID: "test-name", Plugin: nameControl{name: "evil"}},
		Control{ID: "test-vuln", Plugin: vulnControl{name: "evil"}})
	o.Enrichers = []Enricher{{Name: "code", Version: "1", Plugin: newIndexEnricher(0), Local: true}}
	o.Reach = report.ReachInfo{Level: report.ReachImport}
	res := runScan(t, o)
	reaches := map[string]*finding.Reach{}
	for fd, err := range res.Scan.Findings(context.Background(), plugin.FindingQuery{}) {
		require.NoError(t, err)
		reaches[fd.ControlID] = fd.Reach
	}
	require.Contains(t, reaches, "test-vuln")
	assert.Nil(t, reaches["test-name"], "a malware finding gets no reach")
	require.NotNil(t, reaches["test-vuln"])
	assert.Equal(t, finding.ReachImported, reaches["test-vuln"].Level)
}

// failingSource is a source enricher that fails.
type failingSource struct {
	sourceEnricher
	err error
}

func (f *failingSource) Enrich(context.Context, []*model.Package) error { return f.err }

func TestFailedSourceEnricherComputesNoReach(t *testing.T) {
	for _, c := range []struct {
		err  error
		want report.ReachStatus
	}{
		{plugin.ErrUnavailable, report.ReachUnavailable},
		{errors.New("signatures do not load"), report.ReachFailed},
	} {
		t.Run(string(c.want), func(t *testing.T) {
			f := newFixture(t)
			o := f.options(t, project(t), nil, Control{ID: "test-vuln", Plugin: vulnControl{name: "evil"}})
			o.Enrichers = []Enricher{{Name: "code", Version: "1", Plugin: &failingSource{err: c.err}, Local: true}}
			o.Reach = report.ReachInfo{Level: report.ReachImport}
			res := runScan(t, o)
			assert.Equal(t, report.ReachInfo{Level: report.ReachImport, Status: c.want}, *res.Scan.Header().Scan.Reach,
				"a header must not say computed when the code analysis did not run")
			for fd, err := range res.Scan.Findings(context.Background(), plugin.FindingQuery{}) {
				require.NoError(t, err)
				assert.Nil(t, fd.Reach)
			}
		})
	}
}

// vulnControl reports a vulnerability on each package of a name.
type vulnControl struct{ name string }

func (c vulnControl) Evaluate(_ context.Context, m *model.Manifest, _ plugin.State) ([]finding.Finding, error) {
	var out []finding.Finding
	for _, p := range m.Packages {
		if p.ID.RawName() == c.name {
			out = append(out, finding.ForPackage(finding.Meta{
				ControlID: "test-vuln", Family: finding.FamilyVulnerability, Severity: finding.SeverityHigh, Title: "a vulnerability",
			}, m.Path, p, finding.Key{Discriminator: "GHSA-test"}))
		}
	}
	return out, nil
}

// symbolEnricher is a source enricher that read a symbol bundle.
type symbolEnricher struct{ sourceEnricher }

func (*symbolEnricher) SymbolBundle() *report.SymbolBundle {
	return &report.SymbolBundle{ID: "f2e47dc1", Records: 1220}
}

func TestHeaderNamesTheSymbolBundle(t *testing.T) {
	f := newFixture(t)
	o := f.options(t, project(t), nil)
	o.Enrichers = []Enricher{{Name: "code", Version: "1", Plugin: &symbolEnricher{}, Local: true}}
	o.Reach = report.ReachInfo{Level: report.ReachFunction}
	res := runScan(t, o)
	assert.Equal(t, &report.SymbolBundle{ID: "f2e47dc1", Records: 1220}, res.Scan.Header().Scan.Reach.Symbols)
}
