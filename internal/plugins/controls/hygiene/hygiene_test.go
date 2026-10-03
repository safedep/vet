package hygiene_test

import (
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/controls/hygiene"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func npm(name, version string) model.PackageID {
	return model.PackageID{Ecosystem: model.EcosystemNpm, Name: name, Version: version}
}

func ids(t *testing.T, opts map[string]any, m *model.Manifest) []string {
	t.Helper()
	c, err := hygiene.New(plugin.MapConfig(opts))
	require.NoError(t, err)
	var out []string
	for _, f := range plugintest.TestControl(t, c, m, nil) {
		out = append(out, f.ControlID)
	}
	return out
}

func TestInsightChecks(t *testing.T) {
	cases := []struct {
		name string
		opts map[string]any
		pkg  *model.Package
		want []string
	}{
		{"no data", nil, &model.Package{ID: npm("a", "1.0.0")}, nil},
		{"deprecated", nil, &model.Package{ID: npm("a", "1.0.0"), Insight: &model.Insight{Deprecated: true}}, []string{hygiene.IDDeprecated}},
		{"provenance lost", nil, &model.Package{
			ID: npm("a", "2.0.0"), Change: model.ChangeUpgraded, PreviousVersion: "1.0.0",
			Insight: &model.Insight{}, PreviousInsight: &model.Insight{Provenance: true},
		}, []string{hygiene.IDProvenanceLost}},
		{"provenance kept", nil, &model.Package{
			ID: npm("a", "2.0.0"), Change: model.ChangeUpgraded, PreviousVersion: "1.0.0",
			Insight: &model.Insight{Provenance: true}, PreviousInsight: &model.Insight{Provenance: true},
		}, nil},
		{"license change", nil, &model.Package{
			ID: npm("a", "2.0.0"), Change: model.ChangeUpgraded, PreviousVersion: "1.0.0",
			Insight: &model.Insight{Licenses: []string{"AGPL-3.0-only"}}, PreviousInsight: &model.Insight{Licenses: []string{"MIT"}},
		}, []string{hygiene.IDLicenseChange}},
		{"same licenses in another order", nil, &model.Package{
			ID: npm("a", "2.0.0"), Change: model.ChangeUpgraded, PreviousVersion: "1.0.0",
			Insight: &model.Insight{Licenses: []string{"MIT", "Apache-2.0"}}, PreviousInsight: &model.Insight{Licenses: []string{"Apache-2.0", "MIT"}},
		}, nil},
		{"low scorecard", nil, &model.Package{ID: npm("a", "1.0.0"), Insight: &model.Insight{Scorecard: &model.Scorecard{Score: 2.1}}}, []string{hygiene.IDScorecardLow}},
		{"scorecard over the option", map[string]any{"min_scorecard": 2.0}, &model.Package{ID: npm("a", "1.0.0"), Insight: &model.Insight{Scorecard: &model.Scorecard{Score: 2.1}}}, nil},
		{"git source", nil, &model.Package{ID: npm("a", "1.0.0"), Resolved: "git+https://github.com/o/a.git#abc"}, []string{hygiene.IDNonRegistry}},
		{"removed package", nil, &model.Package{ID: npm("a", "1.0.0"), Change: model.ChangeRemoved, Insight: &model.Insight{Deprecated: true}}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := &model.Manifest{ID: "m", Path: "yarn.lock", Kind: model.ManifestKindLockfile, Packages: []*model.Package{tc.pkg}}
			assert.Equal(t, tc.want, ids(t, tc.opts, m))
		})
	}
}

const lock = `{"lockfileVersion": 3, "packages": {
  "": {"name": "app"},
  "node_modules/esbuild": {"version": "0.20.0", "hasInstallScript": true},
  "node_modules/@scope/native": {"version": "1.0.0", "hasInstallScript": true},
  "node_modules/left-pad": {"version": "1.3.0"}
}}`

const pkgJSON = `{
  "name": "app",
  "dependencies": {
    "left-pad": "^1.3.0",
    "mylib": "github:me/mylib",
    "local": "file:../local",
    "anything": "*"
  }
}`

func TestFileChecks(t *testing.T) {
	root := fstest.MapFS{
		"package-lock.json": {Data: []byte(lock)},
		"package.json":      {Data: []byte(pkgJSON)},
		"requirements.txt":  {Data: []byte("requests==2.32.0\ngit+https://github.com/o/r.git#egg=r\n# a comment\n-e ./local\n")},
	}
	m := &model.Manifest{
		ID: "m", Path: "package-lock.json", Kind: model.ManifestKindLockfile, Root: root,
		Packages: []*model.Package{
			{ID: npm("esbuild", "0.20.0"), Change: model.ChangeAdded},
			{ID: model.PackageID{Ecosystem: model.EcosystemNpm, Namespace: "@scope", Name: "native", Version: "1.0.0"}, Change: model.ChangeUpgraded},
			{ID: npm("left-pad", "1.3.0"), Change: model.ChangeAdded},
		},
	}
	got := ids(t, nil, m)
	assert.ElementsMatch(t, []string{
		hygiene.IDInstallScripts, hygiene.IDInstallScripts,
		hygiene.IDNonRegistry, hygiene.IDNonRegistry, hygiene.IDNonRegistry,
	}, got)

	m.Packages[0].Change, m.Packages[1].Change = model.ChangeNone, model.ChangeNone
	assert.NotContains(t, ids(t, nil, m), hygiene.IDInstallScripts, "a full scan has no new dependency")

	req := &model.Manifest{ID: "r", Path: "requirements.txt", Kind: model.ManifestKindManifest, Extractor: "python/requirements", Root: root}
	assert.Equal(t, []string{hygiene.IDNonRegistry, hygiene.IDNonRegistry}, ids(t, nil, req))
}

func TestOptions(t *testing.T) {
	_, err := hygiene.New(plugin.MapConfig(map[string]any{"min_scorecard": 11.0}))
	assert.Error(t, err)
	_, err = hygiene.New(plugin.MapConfig(map[string]any{"nope": 1}))
	assert.Error(t, err)
}
