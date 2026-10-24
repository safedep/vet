package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

func TestReachOf(t *testing.T) {
	app := model.MustPackageVersion(model.EcosystemGo, "example.com/app-lib", "v1.0.0")
	tool := model.MustPackageVersion(model.EcosystemGo, "example.com/test-tool", "v1.0.0")
	dep := model.MustPackageVersion(model.EcosystemGo, "example.com/dep", "v1.0.0")
	lone := model.MustPackageVersion(model.EcosystemGo, "example.com/lone", "v1.0.0")
	far := model.MustPackageVersion(model.EcosystemGo, "example.com/far", "v1.0.0")
	cycle := model.MustPackageVersion(model.EcosystemGo, "example.com/cycle", "v1.0.0")
	newGraph := func(open bool, imports []model.PackageVersion, edges [][2]model.PackageVersion) *model.Graph {
		g := model.NewGraph()
		roots := []model.PackageVersion{app, tool, lone}
		if imports != nil {
			g.SetImports()
			roots = imports
		}
		for _, r := range roots {
			g.AddRoot(r)
		}
		g.AddEdge(app, dep)
		g.AddEdge(tool, dep)
		for _, e := range edges {
			g.AddEdge(e[0], e[1])
		}
		if open {
			g.MarkOpen(lone)
		}
		return g
	}

	stdlib := model.MustPackageVersion(model.EcosystemGo, "stdlib", "1.27.1")
	crate := model.MustPackageVersion(model.EcosystemCargo, "time", "0.3.30")
	site := []model.ImportSite{{File: "index.js", Line: 1}}
	path := []model.PathHop{{Function: "main", File: "main.go", Line: 3, Root: "main"}, {Function: "dep.Render", Edge: "direct", Confidence: model.HopHigh}}
	chaPath := []model.PathHop{{Function: "main", Root: "main"}, {Function: "dep.Render", Edge: "cha", Confidence: "medium"}}
	record := func(r *model.FunctionReach) []model.SymbolRecord {
		return []model.SymbolRecord{{Advisory: "GHSA-test", Coverage: model.CoverageExact, Verified: true, FixSites: []string{"dep.Render"}, Reach: r}}
	}
	cases := []struct {
		name  string
		level report.ReachLevel
		id    model.PackageVersion
		usage *model.Usage
		// appUsage and toolUsage are the usage of the two roots.
		appUsage, toolUsage *model.Usage
		noGraph             bool
		// local adds a local package that the code imports.
		local bool
		// sbom reads the graph from an SBOM, which can list only some edges.
		sbom bool
		// openLone marks lone as a package whose dependencies vet does not
		// know, with the usage loneUsage.
		openLone  bool
		loneUsage *model.Usage
		// imports makes the graph a graph of imports with these roots.
		imports []model.PackageVersion
		// edges adds edges to the graph.
		edges [][2]model.PackageVersion
		want  *finding.Reach
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
			name: "a call path to the fix site of the advisory is called", level: report.ReachFunction,
			usage: &model.Usage{Imported: true, Symbols: []model.SymbolRecord{
				{Advisory: "GHSA-other", FixSites: []string{"a.B"}, Reach: &model.FunctionReach{Status: model.FunctionNotFound}},
				{Advisory: "GHSA-test", Record: "GO-2026-0001", FixSites: []string{"dep.Render"}, Reach: &model.FunctionReach{Status: model.FunctionCalled, Path: path}},
			}},
			want: &finding.Reach{Level: finding.ReachCalled, Confidence: finding.ConfidenceMedium, FixSites: []string{"dep.Render"}, Path: path},
		},
		{
			name: "a call path with a weak call stays imported with the path", level: report.ReachFunction,
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionCalled, Path: chaPath})},
			want:  &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachWeakPath, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}, Path: chaPath},
		},
		{
			name: "no path with a dynamic site stays imported", level: report.ReachFunction,
			usage:    &model.Usage{Imported: true, Dynamic: []model.DynamicSite{{File: "main.go", Line: 4, Kind: "reflect"}}, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})},
			appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachDynamicFlag, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "a call path from a test only", level: report.ReachFunction,
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionCalled, Path: path, TestOnly: true})},
			want:  &finding.Reach{Level: finding.ReachCalled, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}, Path: path, TestOnly: true},
		},
		{
			name: "no path to a package that the project alone imports is not called", level: report.ReachFunction,
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{
				Level: finding.ReachNotCalled, Confidence: finding.ConfidenceMedium, FixSites: []string{"dep.Render"},
				Symbols: &finding.ReachSymbols{Coverage: model.CoverageExact},
			},
		},
		{
			name: "no path to a package that another import depends on stays imported", level: report.ReachFunction,
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, appUsage: &model.Usage{Imported: true}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachTransitive, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "no path to a package that only the graph reaches stays imported", level: report.ReachFunction,
			usage: &model.Usage{Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, appUsage: &model.Usage{Imported: true}, toolUsage: &model.Usage{},
			want: &finding.Reach{
				Level: finding.ReachImported, Cause: finding.ReachTransitive, Confidence: finding.ConfidenceMedium,
				Via: []string{app.PURL(), dep.PURL()}, FixSites: []string{"dep.Render"},
			},
		},
		{
			name: "no path to a package that an unread package depends on stays imported", level: report.ReachFunction,
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachTransitive, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "no path with an imported local package stays imported", level: report.ReachFunction, local: true,
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachTransitive, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "a call in one record of the advisory is a call", level: report.ReachFunction,
			usage: &model.Usage{Imported: true, Symbols: []model.SymbolRecord{
				{Advisory: "GHSA-test", Coverage: model.CoverageExact, Verified: true, FixSites: []string{"dep.Render"}, Reach: &model.FunctionReach{Status: model.FunctionNotFound}},
				{Advisory: "GHSA-test", Coverage: model.CoverageExact, Verified: true, FixSites: []string{"dep.Parse"}, Reach: &model.FunctionReach{Status: model.FunctionCalled, Path: path}},
			}},
			appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachCalled, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render", "dep.Parse"}, Path: path},
		},
		{
			name: "no path in one record and no answer in another stays imported", level: report.ReachFunction,
			usage: &model.Usage{Imported: true, Symbols: []model.SymbolRecord{
				{Advisory: "GHSA-test", Coverage: model.CoverageExact, Verified: true, FixSites: []string{"dep.Render"}, Reach: &model.FunctionReach{Status: model.FunctionNotFound}},
				{Advisory: "GHSA-test", Coverage: "broad", FixSites: []string{"dep.Parse"}, Reach: &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachBroadRecord)}},
			}},
			appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachBroadRecord, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render", "dep.Parse"}},
		},
		{
			name: "an unknown reach of a package that only the graph reaches is transitive", level: report.ReachFunction,
			usage: &model.Usage{Symbols: record(&model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachNoDependencySource)})}, appUsage: &model.Usage{Imported: true}, toolUsage: &model.Usage{},
			want: &finding.Reach{
				Level: finding.ReachImported, Cause: finding.ReachTransitive, Confidence: finding.ConfidenceMedium,
				Via: []string{app.PURL(), dep.PURL()}, FixSites: []string{"dep.Render"},
			},
		},
		{
			name: "no path with the graph of an SBOM stays imported", level: report.ReachFunction, sbom: true,
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachNoGraph, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "no path with an unread file stays imported", level: report.ReachFunction,
			usage: &model.Usage{Imported: true, UnreadFiles: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachUnreadFiles, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "no path with no graph stays imported", level: report.ReachFunction, noGraph: true,
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})},
			want:  &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachNoGraph, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "no path in the standard library stays imported", level: report.ReachFunction, id: stdlib,
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachTransitive, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "no path in a language that the corpus does not prove stays imported", level: report.ReachFunction, id: crate,
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachUnprovenLanguage, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "an unknown function reach keeps its cause", level: report.ReachFunction,
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachNoEntryPoint)})},
			want:  &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachNoEntryPoint, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "a record with no search is a failed analysis", level: report.ReachFunction,
			usage: &model.Usage{Imported: true, Symbols: record(nil)},
			want:  &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachAnalysisFailed, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "an import level scan ignores the call path", level: report.ReachImport,
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})},
			want:  &finding.Reach{Level: finding.ReachImported, Confidence: finding.ConfidenceHigh},
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
			name: "no import and a path only through an open package is unknown", level: report.ReachImport, id: far,
			usage: &model.Usage{}, appUsage: &model.Usage{}, toolUsage: &model.Usage{}, openLone: true, loneUsage: &model.Usage{Imported: true},
			want: &finding.Reach{Level: finding.ReachUnknown, Cause: finding.ReachNoDependencySource, Confidence: finding.ConfidenceLow},
		},
		{
			name: "an open package that the code does not import changes nothing", level: report.ReachImport, id: far,
			usage: &model.Usage{}, appUsage: &model.Usage{}, toolUsage: &model.Usage{}, openLone: true, loneUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachUnused, Confidence: finding.ConfidenceMedium},
		},
		{
			name: "no call path to a package that an open import can reach stays imported", level: report.ReachFunction, id: far,
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			openLone: true, loneUsage: &model.Usage{Imported: true},
			want: &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachNoDependencySource, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "a root of a graph of imports is imported", level: report.ReachImport, id: far, imports: []model.PackageVersion{far},
			usage: &model.Usage{}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Confidence: finding.ConfidenceMedium},
		},
		{
			name: "an import of other code does not reach into a graph of imports", level: report.ReachImport, imports: []model.PackageVersion{lone},
			usage: &model.Usage{}, appUsage: &model.Usage{Imported: true}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachUnused, Confidence: finding.ConfidenceMedium},
		},
		{
			name: "no call path to a package that a root of a graph of imports depends on stays imported", level: report.ReachFunction, imports: []model.PackageVersion{app, dep},
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachTransitive, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "no call path to a package that its own dependency imports stays imported", level: report.ReachFunction, imports: []model.PackageVersion{dep},
			edges: [][2]model.PackageVersion{{dep, cycle}, {cycle, dep}},
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachTransitive, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "no call path to a package that its own open dependency can reach stays imported", level: report.ReachFunction, imports: []model.PackageVersion{dep},
			edges: [][2]model.PackageVersion{{dep, lone}}, openLone: true, loneUsage: &model.Usage{},
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Cause: finding.ReachNoDependencySource, Confidence: finding.ConfidenceHigh, FixSites: []string{"dep.Render"}},
		},
		{
			name: "no call path to a package whose dependencies do not lead back is not called", level: report.ReachFunction, imports: []model.PackageVersion{dep},
			edges: [][2]model.PackageVersion{{dep, cycle}},
			usage: &model.Usage{Imported: true, Symbols: record(&model.FunctionReach{Status: model.FunctionNotFound})}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachNotCalled, Confidence: finding.ConfidenceMedium, FixSites: []string{"dep.Render"}},
		},
		{
			name: "the standard library is imported", level: report.ReachImport, id: stdlib,
			usage: &model.Usage{}, appUsage: &model.Usage{}, toolUsage: &model.Usage{},
			want: &finding.Reach{Level: finding.ReachImported, Confidence: finding.ConfidenceMedium},
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
			id := dep
			if c.id.Name() != "" {
				id = c.id
			}
			target := &model.Package{ID: id, Enrichment: model.Enrichment{Usage: c.usage}}
			kind := model.ManifestKindLockfile
			if c.sbom {
				kind = model.ManifestKindSBOM
			}
			m := &model.Manifest{Kind: kind, Graph: newGraph(c.openLone, c.imports, c.edges), Packages: []*model.Package{
				{ID: app, Enrichment: model.Enrichment{Usage: c.appUsage}},
				{ID: tool, Enrichment: model.Enrichment{Usage: c.toolUsage}},
				{ID: lone, Enrichment: model.Enrichment{Usage: c.loneUsage}},
				target,
			}}
			if c.noGraph {
				m.Graph = nil
			}
			if c.local {
				m.Packages = append(m.Packages, &model.Package{
					ID: model.MustPackageVersion(model.EcosystemGo, "example.com/shared", "v0.1.0"), Local: true,
					Enrichment: model.Enrichment{Usage: &model.Usage{Imported: true}},
				})
			}
			got := reachOf(c.level, target, m, "GHSA-test")
			if got != nil && c.want != nil && c.want.Symbols == nil {
				// One case checks the record details. The others check the level.
				got.Symbols = nil
			}
			assert.Equal(t, c.want, got)
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

// symbolEnricher is a source enricher that read a symbol bundle and
// searched from one entry point.
type symbolEnricher struct{ sourceEnricher }

func (*symbolEnricher) ReachReport(info *report.ReachInfo) {
	info.Symbols = &report.SymbolBundle{ID: "f2e47dc1", Records: 1220}
	info.Roots = &report.ReachRoots{Total: 1, List: []report.EntryPoint{{Function: "main.go//main", Kind: "main"}}}
}

func TestHeaderNamesTheSymbolBundleAndTheRoots(t *testing.T) {
	f := newFixture(t)
	o := f.options(t, project(t), nil)
	o.Enrichers = []Enricher{{Name: "code", Version: "1", Plugin: &symbolEnricher{}, Local: true}}
	o.Reach = report.ReachInfo{Level: report.ReachFunction}
	res := runScan(t, o)
	reach := res.Scan.Header().Scan.Reach
	assert.Equal(t, &report.SymbolBundle{ID: "f2e47dc1", Records: 1220}, reach.Symbols)
	assert.Equal(t, 1, reach.Roots.Total)
}

// grapherEnricher gives each manifest that it gets a graph whose first
// package is open, and records the paths of those manifests.
type grapherEnricher struct {
	sourceEnricher
	paths []string
}

func (g *grapherEnricher) Graph(_ context.Context, m *model.Manifest) (*model.Graph, error) {
	g.paths = append(g.paths, m.Path)
	gr := model.NewGraph()
	gr.MarkOpen(m.Packages[0].ID)
	return gr, nil
}

var _ plugin.Grapher = (*grapherEnricher)(nil)

func TestTheEngineAsksTheGrapherForAManifestWithNoGraph(t *testing.T) {
	f := newFixture(t)
	gr := &grapherEnricher{}
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{
  "name": "app", "version": "1.0.0", "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "version": "1.0.0", "dependencies": {"left-pad": "^1.3.0"}},
    "node_modules/left-pad": {"version": "1.3.0", "dependencies": {"evil": "1.0.0"}},
    "node_modules/evil": {"version": "1.0.0"}
  }
}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("requests==2.31.0\n"), 0o600))
	o := f.options(t, dir, nil)
	o.Enrichers = []Enricher{{Name: "code", Version: "1", Plugin: gr, Local: true}}
	res := runScan(t, o)

	assert.Equal(t, []string{"requirements.txt"}, gr.paths, "a lockfile keeps the graph of its extractor")
	for m, err := range res.Scan.Manifests(context.Background()) {
		require.NoError(t, err)
		require.NotNil(t, m.Graph, m.Path)
		if m.Path == "requirements.txt" {
			assert.Equal(t, []model.PackageVersion{m.Packages[0].ID}, m.Graph.Open(), "the scan file keeps the graph of the grapher")
		}
	}
}
