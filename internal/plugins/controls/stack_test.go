package controls_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/internal/plugins/enrichers"
	"github.com/safedep/vet/v2/internal/plugins/extractors"
	"github.com/safedep/vet/v2/internal/plugins/sources"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/test/acceptance/stub"
)

const lockfile = `{
  "name": "app",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "app", "dependencies": {"left-pad": "1.3.0", "safedep-test-pkg": "0.1.3", "evil": "1.0.0"}},
    "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},
    "node_modules/safedep-test-pkg": {"version": "0.1.3", "resolved": "https://registry.npmjs.org/safedep-test-pkg/-/safedep-test-pkg-0.1.3.tgz"},
    "node_modules/evil": {"version": "1.0.0", "resolved": "https://evil.example.com/evil/-/evil-1.0.0.tgz"}
  }
}
`

const workflow = `on: pull_request_target
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - run: echo "${{ github.event.pull_request.title }}"
`

type settings map[string]map[string]any

func (s settings) PluginEnabled(string, bool) bool { return true }

func (s settings) PluginOptions(name string) map[string]any {
	if o, ok := s[name]; ok {
		return o
	}
	return map[string]any{}
}

func project(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lockfile), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".github", "workflows", "ci.yml"), []byte(workflow), 0o600))
	return dir
}

// TestEveryControlOnAScan runs the built-in controls in a scan of a project
// with the stub enrichers, and checks that each control id fires.
func TestEveryControlOnAScan(t *testing.T) {
	ctx := context.Background()
	s, err := stub.Start(filepath.Join("..", "..", "..", "test", "acceptance", "stub", "fixtures"))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, s.Close()) })

	set, err := enrichers.Build(enrichers.Options{CommunityURL: s.URL(), APIURL: s.URL(), Workers: 2, TTL: time.Hour})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, set.Close()) })
	var ens []engine.Enricher
	for _, sp := range set.Specs {
		ens = append(ens, engine.Enricher{Name: sp.Name, Version: sp.Version, TTL: sp.TTL, Plugin: sp.Plugin})
	}

	// A wide window puts left-pad, published in 2018, inside it.
	built, err := controls.Build(settings{"dependency-cooldown": {"days": 100000}})
	require.NoError(t, err)
	var cs []engine.Control
	for _, c := range built {
		cs = append(cs, engine.Control{ID: c.Name, Plugin: c.Plugin})
	}

	store, err := state.Open(ctx, state.Options{StateDir: t.TempDir()})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, store.Close()) })
	src, err := sources.New(project(t), sources.Options{})
	require.NoError(t, err)

	res, err := engine.Run(ctx, engine.Options{
		Store: store, Source: src, Enrichers: ens, Controls: cs,
		Extractors:  func(plugin.ArtifactKind) ([]plugin.Extractor, error) { return extractors.Default() },
		OptionsHash: "h", VetVersion: "test", BatchSize: 10,
	})
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, res.Scan.Close()) })

	for rec, err := range res.Scan.Records(ctx) {
		require.NoError(t, err)
		assert.Nil(t, rec.Diagnostic, "the scan has no diagnostic")
	}
	got := map[string][]string{}
	for f, err := range res.Scan.Findings(ctx, plugin.FindingQuery{}) {
		require.NoError(t, err)
		subject := ""
		switch {
		case f.Subject.Package != nil:
			subject = f.Subject.Package.Name
		case f.Subject.File != nil:
			subject = f.Subject.File.Path
		}
		got[f.ControlID] = append(got[f.ControlID], subject)
	}
	for _, v := range got {
		sort.Strings(v)
	}
	assert.Equal(t, map[string][]string{
		"dependency-cooldown": {"left-pad"},
		"deprecated-package":  {"left-pad"},
		"malware":             {"safedep-test-pkg"},
		"vulnerability":       {"left-pad"},
		"untrusted-registry":  {"package-lock.json"},
		"dangerous-trigger":   {".github/workflows/ci.yml"},
		"template-injection":  {".github/workflows/ci.yml"},
		"unpinned-action":     {".github/workflows/ci.yml"},
	}, got)
}

// TestBuiltinConformance checks every built-in control with plugintest, on
// manifests with no data and with no file.
func TestBuiltinConformance(t *testing.T) {
	manifests := []*model.Manifest{
		{
			ID: "m1", Path: "package-lock.json", Kind: model.ManifestKindLockfile, Ecosystem: model.EcosystemNpm,
			Packages: []*model.Package{{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Name: "a", Version: "1.0.0"}}},
		},
		{ID: "m2", Path: ".github/workflows/ci.yml", Kind: model.ManifestKindWorkflow, Ecosystem: model.EcosystemGitHubActions},
		{ID: "m3", Path: "pkg:npm/a@1.0.0", Kind: model.ManifestKindPURL, Ecosystem: model.EcosystemNpm},
	}
	for _, spec := range controls.Builtin() {
		for _, m := range manifests {
			t.Run(spec.Name+"/"+m.ID, func(t *testing.T) {
				c, err := spec.New(plugin.MapConfig(nil))
				require.NoError(t, err)
				assert.Empty(t, plugintest.TestControl(t, c, m, nil), "no data gives no finding")
			})
		}
	}
}
