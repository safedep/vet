package license_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/plugins/controls/license"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func pkg(licenses ...string) *model.Package {
	return &model.Package{ID: model.MustPackageVersion(model.EcosystemPyPI, "pyqt5", "5.15.11"), Insight: &model.Insight{Licenses: licenses}}
}

func TestEvaluate(t *testing.T) {
	gpl := []any{"GPL-3.0-only", "GPL-3.0-or-later"}
	cases := []struct {
		name string
		opts map[string]any
		pkg  *model.Package
		want []string
	}{
		{"no lists", nil, pkg("GPL-3.0"), nil},
		{"denied", map[string]any{"deny": gpl}, pkg("GPL-3.0"), []string{license.IDDenied}},
		{"a choice avoids the deny list", map[string]any{"deny": gpl}, pkg("MIT OR GPL-3.0-only"), nil},
		{"not allowed", map[string]any{"allow": []any{"MIT"}}, pkg("Apache-2.0"), []string{license.IDNotAllowed}},
		{"allowed by a set", map[string]any{"allow": []any{"osi-approved"}}, pkg("Apache-2.0"), nil},
		{"deny goes first", map[string]any{"allow": []any{"MIT"}, "deny": gpl}, pkg("MIT AND GPL-3.0-only"), []string{license.IDDenied}},
		{"unknown with an allow list", map[string]any{"allow": []any{"MIT"}}, pkg(), []string{license.IDUnknown}},
		{"free text with an allow list", map[string]any{"allow": []any{"MIT"}}, pkg("BSD"), []string{license.IDUnknown}},
		{"unknown with a deny list", map[string]any{"deny": gpl}, pkg(), nil},
		{"unknown reported on request", map[string]any{"deny": gpl, "unknown": "report"}, pkg(), []string{license.IDUnknown}},
		{"unknown ignored on request", map[string]any{"allow": []any{"MIT"}, "unknown": "ignore"}, pkg(), nil},
		{"no insight", map[string]any{"allow": []any{"MIT"}}, &model.Package{ID: model.MustPackageVersion(model.EcosystemGitHubActions, "actions/checkout", "v4")}, nil},
		{"removed package", map[string]any{"deny": gpl}, &model.Package{
			ID: model.MustPackageVersion(model.EcosystemPyPI, "pyqt5", "5.15.11"), Change: model.ChangeRemoved,
			Insight: &model.Insight{Licenses: []string{"GPL-3.0"}},
		}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := license.New(plugin.MapConfig(tc.opts))
			require.NoError(t, err)
			m := &model.Manifest{ID: "m", Path: "requirements.txt", Kind: model.ManifestKindManifest, Packages: []*model.Package{tc.pkg}}
			var got []string
			for _, f := range plugintest.TestControl(t, c, m, nil) {
				got = append(got, f.ControlID)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFinding(t *testing.T) {
	c, err := license.New(plugin.MapConfig(map[string]any{"deny": []any{"GPL-3.0-only"}}))
	require.NoError(t, err)
	m := &model.Manifest{ID: "m", Path: "requirements.txt", Kind: model.ManifestKindManifest, Packages: []*model.Package{pkg("GPL-3.0")}}
	fs := plugintest.TestControl(t, c, m, nil)
	require.Len(t, fs, 1)
	f := fs[0]
	assert.Equal(t, "pypi/pyqt5@5.15.11 has the denied license GPL-3.0", f.Title)
	require.Len(t, f.Evidence, 1)
	assert.Contains(t, f.Evidence[0].Summary, "The declared license is GPL-3.0. vet checks it with the SPDX License List ")
	assert.NotEmpty(t, f.Remediation.Summary)
}

func TestNewRejectsOptions(t *testing.T) {
	cases := []struct {
		name string
		opts map[string]any
		want string
	}{
		{"an expression in a list", map[string]any{"allow": []any{"MIT OR Apache-2.0"}}, "license: allow:"},
		{"a name that is not SPDX", map[string]any{"deny": []any{"GPL"}}, "license: deny:"},
		{"a bad unknown value", map[string]any{"unknown": "warn"}, `license: unknown "warn"`},
		{"an unknown option", map[string]any{"globs": true}, "globs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := license.New(plugin.MapConfig(tc.opts))
			assert.ErrorContains(t, err, tc.want)
		})
	}
}
