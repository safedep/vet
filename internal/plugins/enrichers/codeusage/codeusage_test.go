package codeusage

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func TestEnrich(t *testing.T) {
	calls := 0
	fake := func(context.Context, string) ([]Evidence, error) {
		calls++
		return []Evidence{
			{PackageHint: "lodash", ModuleName: "lodash/fp", FilePath: "src/b.js"},
			{PackageHint: "lodash", ModuleName: "lodash", FilePath: "src/a.js"},
			{ModuleName: "@scope/pkg/sub", FilePath: "src/c.js"},
			{PackageHint: "yaml", ModuleName: "yaml", FilePath: "app.py"},
			{PackageHint: "python_dateutil", ModuleName: "dateutil", FilePath: "app.py"},
		}, nil
	}
	e := NewWith("/repo", fake)
	pkgs := []*model.Package{
		{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "lodash", Version: "4.17.21"}},
		{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Namespace: "@scope", Name: "pkg", Version: "1.0.0"}},
		{ID: model.PackageID{Ecosystem: model.EcosystemPyPI, Name: "python-dateutil", Version: "2.9.0"}},
		{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "unused", Version: "1.0.0"}},
	}
	plugintest.TestEnricher(t, e, pkgs)
	assert.Equal(t, 1, calls, "the analysis runs once for a scan")
	assert.Equal(t, &model.Usage{Imported: true, Files: []string{"src/a.js", "src/b.js"}}, pkgs[0].Usage)
	assert.True(t, pkgs[1].Usage.Imported)
	assert.True(t, pkgs[2].Usage.Imported, "PyPI names match with underscores")
	assert.Equal(t, &model.Usage{}, pkgs[3].Usage)
}

func TestEnrichError(t *testing.T) {
	e := NewWith("/repo", func(context.Context, string) ([]Evidence, error) {
		return nil, plugin.ErrUnavailable
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
