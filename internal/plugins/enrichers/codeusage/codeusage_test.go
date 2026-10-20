package codeusage

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			Files:     map[string]string{"a.js": "indexed", "b.js": FileMissing, "c.js": FileMissing},
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
