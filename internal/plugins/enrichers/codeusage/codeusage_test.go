package codeusage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/safedep/code/fileindex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/symbols"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

func TestEnrich(t *testing.T) {
	calls := 0
	fake := func(context.Context, string) (Analysis, error) {
		calls++
		return Analysis{Usage: []Evidence{
			{PackageHint: "lodash", ModuleName: "lodash/fp", FilePath: "src/b.js", Line: 4},
			{PackageHint: "lodash", ModuleName: "lodash", FilePath: "src/b.js", Line: 2},
			{PackageHint: "lodash", ModuleName: "lodash", FilePath: "src/a.js", Line: 1},
			{PackageHint: "jest", ModuleName: "jest", FilePath: "src/a.test.js", Line: 1},
			{PackageHint: "jest", ModuleName: "jest", FilePath: "test/setup.js", Line: 3},
			{ModuleName: "@scope/pkg/sub", FilePath: "src/c.js"},
			{PackageHint: "yaml", ModuleName: "yaml", FilePath: "app.py"},
			{PackageHint: "python_dateutil", ModuleName: "dateutil", FilePath: "app.py"},
		}, Languages: map[string]bool{"javascript": true, "python": true}}, nil
	}
	e := NewWith("/repo", Options{}, fake)
	pkgs := []*model.Package{
		{ID: model.MustPackageVersion(model.EcosystemNpm, "lodash", "4.17.21")},
		{ID: model.MustPackageVersion(model.EcosystemNpm, "@scope/pkg", "1.0.0")},
		{ID: model.MustPackageVersion(model.EcosystemPyPI, "python-dateutil", "2.9.0")},
		{ID: model.MustPackageVersion(model.EcosystemNpm, "unused", "1.0.0")},
		{ID: model.MustPackageVersion(model.EcosystemGitHubActions, "actions/checkout", "v4")},
		{ID: model.MustPackageVersion(model.EcosystemNpm, "jest", "29.0.0")},
	}
	plugintest.TestEnricher(t, e, pkgs)
	assert.Equal(t, 1, calls, "the analysis runs once for a scan")
	assert.Equal(t, &model.Usage{
		Imported: true, Files: []string{"src/a.js", "src/b.js"},
		Imports: []model.ImportSite{{File: "src/a.js", Line: 1}, {File: "src/b.js", Line: 2}},
	}, pkgs[0].Usage, "each file gives its first import")
	assert.True(t, pkgs[1].Usage.Imported)
	assert.True(t, pkgs[2].Usage.Imported, "PyPI names match with underscores")
	assert.Equal(t, &model.Usage{}, pkgs[3].Usage)
	assert.Nil(t, pkgs[4].Usage, "an action has no source imports")
	assert.True(t, pkgs[5].Usage.TestOnly, "only test files import jest")
	assert.False(t, pkgs[0].Usage.TestOnly)
}

func TestBudgetKeepsThePartialAnalysis(t *testing.T) {
	analyze := func(ctx context.Context, _ string) (Analysis, error) {
		<-ctx.Done()
		return Analysis{
			Usage:     []Evidence{{PackageHint: "a", ModuleName: "a", FilePath: "a.js", Line: 1}},
			Files:     map[string]fileindex.FileStatus{"a.js": fileindex.FileIndexed, "b.js": fileindex.FileMissing, "c.js": fileindex.FileMissing},
			Languages: map[string]bool{"javascript": true},
		}, ctx.Err()
	}
	e := NewWith(t.TempDir(), Options{Budget: time.Millisecond}, analyze)
	pkgs := []*model.Package{
		{ID: model.MustPackageVersion(model.EcosystemNpm, "a", "1.0.0")},
		{ID: model.MustPackageVersion(model.EcosystemNpm, "b", "1.0.0")},
	}
	require.NoError(t, e.Enrich(context.Background(), pkgs), "the budget stops the analysis, not the scan")
	assert.True(t, pkgs[0].Usage.Imported)
	assert.Equal(t, &model.Usage{Incomplete: true}, pkgs[1].Usage, "a missing file can import b")
	diags := e.Diagnostics()
	require.Len(t, diags, 1)
	assert.Equal(t, CodeFileMissing, diags[0].Code)
	assert.Contains(t, diags[0].Message, "2 source files")
}

func TestScanDeadlineStopsTheAnalysis(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	<-ctx.Done()
	analyze := func(ctx context.Context, _ string) (Analysis, error) { return Analysis{}, ctx.Err() }
	e := NewWith(t.TempDir(), Options{Budget: time.Hour}, analyze)
	assert.ErrorIs(t, e.Enrich(ctx, nil), context.DeadlineExceeded, "the deadline of the scan is not the budget")
}

func TestCanceledScanStopsTheAnalysis(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	analyze := func(ctx context.Context, _ string) (Analysis, error) { return Analysis{}, ctx.Err() }
	e := NewWith(t.TempDir(), Options{Budget: time.Hour}, analyze)
	assert.ErrorIs(t, e.Enrich(ctx, nil), context.Canceled)
}

func TestFilesKeepTheAnalyzerPaths(t *testing.T) {
	e := NewWith(t.TempDir(), Options{}, func(context.Context, string) (Analysis, error) {
		return Analysis{Usage: []Evidence{
			{PackageHint: "a", FilePath: filepath.Join("src", "a.js")},
			{PackageHint: "a", FilePath: "lib/b.js"},
		}}, nil
	})
	pkgs := []*model.Package{{ID: model.MustPackageVersion(model.EcosystemNpm, "a", "1.0.0")}}
	require.NoError(t, e.Enrich(context.Background(), pkgs))
	assert.Equal(t, []string{"lib/b.js", "src/a.js"}, pkgs[0].Usage.Files, "safedep/code names each file relative to the target")
}

func TestDiagnosticsOfFailedFiles(t *testing.T) {
	var failed []FileFailure
	for i := range maxFailedNames + 2 {
		failed = append(failed, FileFailure{FilePath: fmt.Sprintf("f%d.py", i), Stage: "parse", Err: "too large"})
	}
	cases := []struct {
		name   string
		failed []FileFailure
		want   []string
	}{
		{"no failure", nil, nil},
		{"one failure", failed[:1], []string{"vet could not analyze 1 source files", "f0.py (parse)"}},
		{"more failures than names", failed, []string{"7 source files", "f4.py (parse)", "and 2 more"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := NewWith(t.TempDir(), Options{}, func(context.Context, string) (Analysis, error) {
				return Analysis{Failed: tc.failed}, nil
			})
			require.NoError(t, e.Enrich(context.Background(), nil))
			diags := e.Diagnostics()
			if tc.want == nil {
				assert.Empty(t, diags)
				return
			}
			require.Len(t, diags, 1)
			assert.Equal(t, CodeFileFailed, diags[0].Code)
			assert.Equal(t, report.DiagnosticWarning, diags[0].Level)
			for _, w := range tc.want {
				assert.Contains(t, diags[0].Message, w)
			}
			assert.NotContains(t, diags[0].Message, "f5.py", "the message lists at most maxFailedNames files")
		})
	}
}

func TestEnrichError(t *testing.T) {
	e := NewWith("/repo", Options{}, func(context.Context, string) (Analysis, error) {
		return Analysis{}, plugin.ErrUnavailable
	})
	err := e.Enrich(context.Background(), []*model.Package{{ID: model.MustPackageVersion(model.EcosystemNpm, "a", "1")}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, plugin.ErrUnavailable))
}

func TestRootModule(t *testing.T) {
	for in, want := range map[string]string{"lodash/fp": "lodash", "@scope/pkg/sub": "@scope/pkg", "yaml.loader": "yaml", "requests": "requests", "@x": "@x"} {
		assert.Equal(t, want, rootModule(in), in)
	}
}

func TestNoSourceGivesNoUsage(t *testing.T) {
	calls := 0
	e := NewWith(t.TempDir(), Options{}, func(context.Context, string) (Analysis, error) {
		calls++
		return Analysis{}, nil
	})
	e.UseSource("")
	pkgs := []*model.Package{{ID: model.MustPackageVersion(model.EcosystemNpm, "a", "1.0.0")}}
	require.NoError(t, e.Prepare(context.Background()))
	require.NoError(t, e.Enrich(context.Background(), pkgs))
	caps, err := e.Capabilities(context.Background())
	require.NoError(t, err)
	assert.Nil(t, pkgs[0].Usage)
	assert.Empty(t, caps)
	assert.Zero(t, calls, "a target with no source code needs no analysis")
}

func TestDynamicImportMarksTheEcosystem(t *testing.T) {
	e := NewWith(t.TempDir(), Options{}, func(context.Context, string) (Analysis, error) {
		return Analysis{DynamicImports: map[string]bool{"python": true}}, nil
	})
	pkgs := []*model.Package{
		{ID: model.MustPackageVersion(model.EcosystemPyPI, "yaml", "6.0")},
		{ID: model.MustPackageVersion(model.EcosystemNpm, "a", "1.0.0")},
	}
	require.NoError(t, e.Enrich(context.Background(), pkgs))
	assert.True(t, pkgs[0].Usage.DynamicImport)
	assert.False(t, pkgs[1].Usage.DynamicImport, "a computed Python import says nothing about npm")
}

func TestCallsAreBoundedAndMapped(t *testing.T) {
	var calls []ExternalCall
	for i := range maxSites + 50 {
		calls = append(calls, ExternalCall{FilePath: "a.js", Line: i + 1, Language: "javascript", Callee: "lodash//map", Module: "lodash"})
	}
	calls = append(calls, ExternalCall{FilePath: "a.js", Line: 1, Language: "javascript", Callee: "axios//get", Module: "axios"})
	e := NewWith(t.TempDir(), Options{}, func(context.Context, string) (Analysis, error) {
		return Analysis{
			Usage: []Evidence{{PackageHint: "lodash", ModuleName: "lodash", Language: "javascript", FilePath: "a.js", Line: 1}},
			Calls: calls,
		}, nil
	})
	lodash := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "lodash", "4.17.21")}
	axios := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "axios", "1.0.0")}
	require.NoError(t, e.Enrich(context.Background(), []*model.Package{lodash, axios}))
	assert.Len(t, lodash.Usage.Calls, maxSites)
	assert.Equal(t, model.CallSite{File: "a.js", Line: 1, Callee: "lodash//map"}, lodash.Usage.Calls[0], "the calls are in line order")
	assert.Equal(t, []model.CallSite{{File: "a.js", Line: 1, Callee: "axios//get"}}, axios.Usage.Calls, "a call counts for the package of its module only")
}

func TestUnreadAndMissingLanguages(t *testing.T) {
	e := NewWith(t.TempDir(), Options{}, func(context.Context, string) (Analysis, error) {
		return Analysis{
			Languages: map[string]bool{"python": true, "go": true},
			Unread:    map[string]bool{"python": true},
		}, nil
	})
	pypi := &model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, "yaml", "6.0")}
	golang := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, "golang.org/x/net", "v0.20.0")}
	npm := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "left-pad", "1.3.0")}
	require.NoError(t, e.Enrich(context.Background(), []*model.Package{pypi, golang, npm}))
	assert.True(t, pypi.Usage.UnreadFiles, "a Python file failed, so a Python import can hide in it")
	assert.False(t, golang.Usage.UnreadFiles)
	assert.False(t, golang.Usage.NoSourceFiles)
	assert.True(t, npm.Usage.NoSourceFiles, "no JavaScript file parsed, so no import proves nothing")
}

// symbolSource answers every query with one record.
type symbolSource struct {
	prepared int
	verified bool
	edit     func(*model.SymbolRecord)
}

func (s *symbolSource) Prepare(context.Context) { s.prepared++ }
func (s *symbolSource) Lookup(qs []symbols.Query) [][]model.SymbolRecord {
	out := make([][]model.SymbolRecord, len(qs))
	for i, q := range qs {
		r := model.SymbolRecord{Advisory: q.IDs[0], Record: "GO-2026-0001", Coverage: "exact", Verified: s.verified, FixSites: []string{"golang.org/x/net/html.Render"}}
		if s.edit != nil {
			s.edit(&r)
		}
		out[i] = []model.SymbolRecord{r}
	}
	return out
}
func (s *symbolSource) Diagnostics() []report.Diagnostic { return nil }
func (s *symbolSource) Bundle() *report.SymbolBundle {
	return &report.SymbolBundle{ID: "abc", Records: 1}
}

func TestSymbolsOfGoRustAndPythonVulnerabilities(t *testing.T) {
	src := &symbolSource{}
	analysis := Analysis{Languages: map[string]bool{"go": true, "python": true, "javascript": true}}
	e := NewWith(t.TempDir(), Options{Symbols: src}, func(context.Context, string) (Analysis, error) { return analysis, nil })
	vuln := &model.Insight{Vulnerabilities: []model.Vulnerability{{ID: "GHSA-aaaa", Aliases: []string{"CVE-2026-0001"}}}}
	net := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, "golang.org/x/net", "v0.20.0"), Enrichment: model.Enrichment{Insight: vuln}}
	yaml := &model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, "pyyaml", "5.0"), Enrichment: model.Enrichment{Insight: vuln}}
	pad := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "left-pad", "1.3.0"), Enrichment: model.Enrichment{Insight: vuln}}
	require.NoError(t, e.Enrich(context.Background(), []*model.Package{net, yaml, pad}))
	assert.Equal(t, 1, src.prepared)
	assert.Equal(t, []model.SymbolRecord{{
		Advisory: "GHSA-aaaa", Record: "GO-2026-0001", Coverage: "exact",
		FixSites: []string{"golang.org/x/net/html.Render"}, Keys: []string{"golang.org//x//net//html//Render"},
	}}, net.Usage.Symbols)
	require.Len(t, yaml.Usage.Symbols, 1)
	assert.Equal(t, []string{"golang//org/x/net/html//Render"}, yaml.Usage.Symbols[0].Keys, "a Python record gets the key of the dotted name of each fix site")
	assert.Empty(t, pad.Usage.Symbols, "the symbol data covers Go, Rust and Python only")
	var info report.ReachInfo
	e.ReachReport(&info)
	assert.Equal(t, "abc", info.Symbols.ID)
	assert.Nil(t, info.Roots, "a record with no key searches no call path")
}

func TestNoGoRustOrPythonCodeReadsNoSymbolData(t *testing.T) {
	src := &symbolSource{}
	e := NewWith(t.TempDir(), Options{Symbols: src}, func(context.Context, string) (Analysis, error) {
		return Analysis{Languages: map[string]bool{"javascript": true}}, nil
	})
	require.NoError(t, e.Enrich(context.Background(), nil))
	assert.Zero(t, src.prepared, "a project with no Go, Rust or Python code needs no symbol bundle")
	var info report.ReachInfo
	e.ReachReport(&info)
	assert.Equal(t, report.ReachInfo{}, info)
}

func TestFunctionReachOfARecord(t *testing.T) {
	const key = "golang.org//x//net//html//Render"
	path := []model.PathHop{{Function: "main.go//main", Root: "main"}, {Function: key}}
	cases := []struct {
		name     string
		vendored bool
		indirect bool
		record   func(*model.SymbolRecord)
		answer   ReachAnswer
		err      error
		want     *model.FunctionReach
		diag     string
	}{
		{
			name: "a path to a fix site is a call", vendored: true,
			answer: ReachAnswer{Status: ReachFound, Path: path},
			want:   &model.FunctionReach{Status: model.FunctionCalled, Path: path},
		},
		{
			name: "no path in an exact and verified record of vendored code", vendored: true,
			answer: ReachAnswer{Status: ReachNotFound},
			want:   &model.FunctionReach{Status: model.FunctionNotFound},
		},
		{
			name: "no path with no source of the package", answer: ReachAnswer{Status: ReachNotFound},
			want: &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachNoDependencySource)}, diag: CodeSourceMissing,
		},
		{
			name: "a package that the code does not import gives no code", vendored: true, indirect: true, answer: ReachAnswer{Status: ReachNotFound},
			want: &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachNoDependencySource)},
		},
		{
			name: "no definition with no source of the package", answer: ReachAnswer{Status: ReachNoSuchTarget},
			want: &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachNoDependencySource)},
		},
		{
			name: "no definition in the source of the package", vendored: true, answer: ReachAnswer{Status: ReachNoSuchTarget},
			want: &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachNoSymbolInGraph)},
		},
		{
			name: "no path in a broad record", vendored: true, answer: ReachAnswer{Status: ReachNotFound},
			record: func(r *model.SymbolRecord) { r.Coverage = "broad" },
			want:   &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachBroadRecord)},
		},
		{
			name: "no path in an unreviewed record", vendored: true, answer: ReachAnswer{Status: ReachNotFound},
			record: func(r *model.SymbolRecord) { r.Verified = false },
			want:   &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachUnreviewedRecord)},
		},
		{
			name: "an unresolved call", vendored: true, answer: ReachAnswer{Status: ReachUncertain, Uncertain: "unresolved-call"},
			want: &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachUnresolvedCall)},
		},
		{
			name: "no entry point", vendored: true, answer: ReachAnswer{Status: ReachNotFound, RootFallback: true},
			want: &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachNoEntryPoint)},
		},
		{
			name: "a failed search", vendored: true, err: errors.New("link the call graph: boom"),
			want: &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachAnalysisFailed)}, diag: CodeReachFailed,
		},
		{
			name: "a search past its budget", vendored: true, err: context.DeadlineExceeded,
			want: &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachBudget)}, diag: CodeReachStopped,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			if c.vendored {
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "vendor", "golang.org", "x", "net"), 0o755))
				require.NoError(t, os.WriteFile(filepath.Join(dir, "vendor", "modules.txt"), []byte("# golang.org/x/net v0.20.0\n"), 0o600))
			}
			t.Setenv("GOMODCACHE", t.TempDir())
			src := &symbolSource{verified: true}
			if c.record != nil {
				src.edit = c.record
			}
			analysis := Analysis{Languages: map[string]bool{"go": true}, Reach: func(_ context.Context, q ReachQuery) (ReachResult, error) {
				assert.Equal(t, []string{key}, q.Targets)
				assert.Equal(t, c.vendored && !c.indirect, len(q.Units) == 1, "only an imported package gives its code")
				return ReachResult{Answers: map[string]ReachAnswer{key: c.answer}}, c.err
			}}
			if !c.indirect {
				analysis.Usage = []Evidence{{Language: "go", PackageHint: "golang.org/x/net", ModuleName: "golang.org/x/net/html", FilePath: "main.go", Line: 3}}
			}
			e := NewWith(dir, Options{Symbols: src}, func(context.Context, string) (Analysis, error) { return analysis, nil })
			vuln := &model.Insight{Vulnerabilities: []model.Vulnerability{{ID: "GHSA-aaaa"}}}
			net := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, "golang.org/x/net", "v0.20.0"), Enrichment: model.Enrichment{Insight: vuln}}
			require.NoError(t, e.Enrich(context.Background(), []*model.Package{net}))
			require.Len(t, net.Usage.Symbols, 1)
			assert.Equal(t, c.want, net.Usage.Symbols[0].Reach)
			var codes []string
			for _, d := range e.Diagnostics() {
				codes = append(codes, d.Code)
			}
			if c.diag != "" {
				assert.Contains(t, codes, c.diag)
			}
		})
	}
}

func TestEntryPointUsageErrorStopsTheEnricher(t *testing.T) {
	analysis := Analysis{Languages: map[string]bool{"go": true}, Reach: func(context.Context, ReachQuery) (ReachResult, error) {
		return ReachResult{}, app.UsageError("entry point \"x\" is not path:function", "Fix it.")
	}}
	e := NewWith(t.TempDir(), Options{Symbols: &symbolSource{}}, func(context.Context, string) (Analysis, error) { return analysis, nil })
	vuln := &model.Insight{Vulnerabilities: []model.Vulnerability{{ID: "GHSA-aaaa"}}}
	net := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, "golang.org/x/net", "v0.20.0"), Enrichment: model.Enrichment{Insight: vuln}}
	err := e.Enrich(context.Background(), []*model.Package{net})
	assert.Equal(t, app.ExitUsage, app.ExitCode(err))
}

func TestFunctionReachOfKeys(t *testing.T) {
	const a, b = "x//A", "x//B"
	record := func(keys ...string) *model.SymbolRecord {
		return &model.SymbolRecord{Coverage: model.CoverageExact, Verified: true, FixSites: []string{"x.A", "x.B"}, Keys: keys}
	}
	notFound := map[string]ReachAnswer{a: {Status: ReachNotFound}, b: {Status: ReachNotFound}}
	assert.Equal(t, model.FunctionNotFound, functionReachOf(record(a, b), notFound, true, "").Status)
	assert.Equal(t, &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachNoSymbolInGraph)},
		functionReachOf(record(a), notFound, true, ""), "a fix site with no key leaves a hole in the search")
	assert.Equal(t, &model.FunctionReach{Status: model.FunctionUnknown, Cause: string(finding.ReachNoSymbolInGraph)},
		functionReachOf(record(a, b), map[string]ReachAnswer{a: {Status: ReachNotFound}, b: {Status: ReachNoSuchTarget}}, true, ""),
		"one key that the graph does not hold leaves a hole")
	called := map[string]ReachAnswer{a: {Status: ReachFound, TestOnly: true}, b: {Status: ReachFound, Path: []model.PathHop{{Function: "main"}}}}
	assert.Equal(t, &model.FunctionReach{Status: model.FunctionCalled, Path: []model.PathHop{{Function: "main"}}},
		functionReachOf(record(a, b), called, true, ""), "a path that is not from a test wins")
}

func TestMissingSourceDiagnostics(t *testing.T) {
	many := []string{"a", "b", "c", "d", "e", "f", "g"}
	cases := []struct {
		name   string
		noCode map[model.Ecosystem][]string
		want   []string
	}{
		{
			name:   "one Go module names Go only",
			noCode: map[model.Ecosystem][]string{model.EcosystemGo: {"golang.org/x/net", "golang.org/x/net"}},
			want:   []string{"vet found no code for 1 vulnerable Go module (golang.org/x/net), so it cannot tell if the code calls the vulnerable functions. Run go mod download, then scan again."},
		},
		{
			name:   "each ecosystem has its own diagnostic",
			noCode: map[model.Ecosystem][]string{model.EcosystemGo: {"golang.org/x/net"}, model.EcosystemCargo: {"hyper", "tokio"}},
			want: []string{
				"vet found no code for 2 vulnerable Rust crates (hyper, tokio), so it cannot tell if the code calls the vulnerable functions. Run cargo fetch, then scan again.",
				"vet found no code for 1 vulnerable Go module (golang.org/x/net), so it cannot tell if the code calls the vulnerable functions. Run go mod download, then scan again.",
			},
		},
		{
			name:   "a Python distribution says to install the project",
			noCode: map[model.Ecosystem][]string{model.EcosystemPyPI: {"PyYAML"}},
			want:   []string{"vet found no code for 1 vulnerable Python distribution (PyYAML), so it cannot tell if the code calls the vulnerable functions. Install the project in a virtual environment, as pip install -r requirements.txt or uv sync, then scan again."},
		},
		{
			name:   "a long list names the first packages",
			noCode: map[model.Ecosystem][]string{model.EcosystemGo: many},
			want:   []string{"vet found no code for 7 vulnerable Go modules (a, b, c, d, e and 2 more), so it cannot tell if the code calls the vulnerable functions. Run go mod download, then scan again."},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := &Enricher{noCode: c.noCode}
			var got []string
			for _, d := range e.missingDiagnostics() {
				assert.Equal(t, CodeSourceMissing, d.Code)
				got = append(got, d.Message)
			}
			assert.Equal(t, c.want, got)
		})
	}
}

func TestCallsIntoKeepsTheLineOrderAcrossModules(t *testing.T) {
	e := &Enricher{calls: []ExternalCall{
		{FilePath: "a.js", Line: 1, Language: "javascript", Callee: "lodash//map", Module: "lodash"},
		{FilePath: "a.js", Line: 2, Language: "javascript", Callee: "lodash/fp//map", Module: "lodash/fp"},
		{FilePath: "a.js", Line: 3, Language: "javascript", Callee: "axios//get", Module: "axios"},
		{FilePath: "b.js", Line: 1, Language: "javascript", Callee: "lodash//pick", Module: "lodash"},
	}}
	got := e.callsInto(model.MustPackageVersion(model.EcosystemNpm, "lodash", "4.17.21"), e.callModules())
	assert.Equal(t, []model.CallSite{
		{File: "a.js", Line: 1, Callee: "lodash//map"},
		{File: "a.js", Line: 2, Callee: "lodash/fp//map"},
		{File: "b.js", Line: 1, Callee: "lodash//pick"},
	}, got)
}
