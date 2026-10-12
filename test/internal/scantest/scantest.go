// Package scantest runs the extractors and the controls of a default scan
// in the test process, with no enricher and no network. The evasion corpus
// and the false-positive run share it, so both scan a target as vet scan
// does.
package scantest

import (
	"context"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/endpoint/inventory"
	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/internal/plugins/extractors"
	"github.com/safedep/vet/v2/internal/plugins/sources"
	"github.com/safedep/vet/v2/internal/plugins/sources/endpoint"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
)

type allEnabled struct{}

func (allEnabled) PluginEnabled(string, bool) bool     { return true }
func (allEnabled) PluginOrigin(string, string) string  { return "" }
func (allEnabled) PluginOptions(string) map[string]any { return map[string]any{} }

// Directory returns the source of a directory scan of dir.
func Directory(t *testing.T, dir string) plugin.Source {
	t.Helper()
	src, err := sources.New(dir, sources.Options{})
	require.NoError(t, err)
	return src
}

// Endpoint returns the source of vet endpoint audit on a machine whose home
// folder is home, with no inventory scanner.
func Endpoint(home string) plugin.Source {
	return endpoint.New(endpoint.Options{}, endpoint.System{
		Hostname: func() (string, error) { return "scantest", nil },
		Home:     func() (string, error) { return home, nil },
		Scanners: func() ([]inventory.Scanner, error) { return nil, nil },
	})
}

// Scan runs the built-in controls on src and returns the findings.
func Scan(t *testing.T, src plugin.Source) []*finding.Finding {
	t.Helper()
	ctx := context.Background()
	built, err := controls.Build(allEnabled{})
	require.NoError(t, err)
	cs := make([]engine.Control, 0, len(built))
	for _, c := range built {
		cs = append(cs, engine.Control{ID: c.Name, Plugin: c.Plugin})
	}
	store, err := state.Open(ctx, state.Options{StateDir: t.TempDir()})
	require.NoError(t, err)
	defer func() { assert.NoError(t, store.Close()) }()
	res, err := engine.Run(ctx, engine.Options{
		Store: store, Source: src, Controls: cs,
		Extractors:  func(plugin.ArtifactKind) ([]plugin.Extractor, error) { return extractors.For(model.PackagesDeclared) },
		OptionsHash: "scantest", VetVersion: "test", BatchSize: 10,
	})
	require.NoError(t, err)
	defer func() { assert.NoError(t, res.Scan.Close()) }()
	var out []*finding.Finding
	for f, err := range res.Scan.Findings(ctx, plugin.FindingQuery{}) {
		require.NoError(t, err)
		out = append(out, f)
	}
	return out
}

// ControlIDs returns the sorted control ids of findings, each one once.
func ControlIDs(fs []*finding.Finding) []string {
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.ControlID)
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}
