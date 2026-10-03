package codeusage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func TestEnrich(t *testing.T) {
	calls := 0
	fake := func(context.Context, string) (Analysis, error) {
		calls++
		return Analysis{Usage: []Evidence{
			{PackageHint: "lodash", ModuleName: "lodash/fp", FilePath: "src/b.js"},
			{PackageHint: "lodash", ModuleName: "lodash", FilePath: "src/a.js"},
			{ModuleName: "@scope/pkg/sub", FilePath: "src/c.js"},
			{PackageHint: "yaml", ModuleName: "yaml", FilePath: "app.py"},
			{PackageHint: "python_dateutil", ModuleName: "dateutil", FilePath: "app.py"},
		}}, nil
	}
	e := NewWith("/repo", Options{}, fake)
	pkgs := []*model.Package{
		{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "lodash", Version: "4.17.21"}},
		{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Namespace: "@scope", Name: "pkg", Version: "1.0.0"}},
		{ID: model.PackageID{Ecosystem: model.EcosystemPyPI, Name: "python-dateutil", Version: "2.9.0"}},
		{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "unused", Version: "1.0.0"}},
		{ID: model.PackageID{Ecosystem: model.EcosystemGitHubActions, Namespace: "actions", Name: "checkout", Version: "v4"}},
	}
	plugintest.TestEnricher(t, e, pkgs)
	assert.Equal(t, 1, calls, "the analysis runs once for a scan")
	assert.Equal(t, &model.Usage{Imported: true, Files: []string{"src/a.js", "src/b.js"}}, pkgs[0].Usage)
	assert.True(t, pkgs[1].Usage.Imported)
	assert.True(t, pkgs[2].Usage.Imported, "PyPI names match with underscores")
	assert.Equal(t, &model.Usage{}, pkgs[3].Usage)
	assert.Nil(t, pkgs[4].Usage, "an action has no source imports")
}

func TestRelativeFiles(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "other", "x.js")
	e := NewWith(root, Options{}, func(context.Context, string) (Analysis, error) {
		return Analysis{Usage: []Evidence{
			{PackageHint: "a", FilePath: filepath.Join(root, "src", "a.js")},
			{PackageHint: "a", FilePath: "lib/b.js"},
			{PackageHint: "a", FilePath: outside},
		}}, nil
	})
	pkgs := []*model.Package{{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "a", Version: "1.0.0"}}}
	require.NoError(t, e.Enrich(context.Background(), pkgs))
	want := []string{"lib/b.js", "src/a.js", outside}
	assert.ElementsMatch(t, want, pkgs[0].Usage.Files)
}

func TestEnrichError(t *testing.T) {
	e := NewWith("/repo", Options{}, func(context.Context, string) (Analysis, error) {
		return Analysis{}, plugin.ErrUnavailable
	})
	err := e.Enrich(context.Background(), []*model.Package{{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "a", Version: "1"}}})
	require.Error(t, err)
	assert.True(t, errors.Is(err, plugin.ErrUnavailable))
}

func TestRootModule(t *testing.T) {
	for in, want := range map[string]string{"lodash/fp": "lodash", "@scope/pkg/sub": "@scope/pkg", "yaml.loader": "yaml", "requests": "requests", "@x": "@x"} {
		assert.Equal(t, want, rootModule(in), in)
	}
}
