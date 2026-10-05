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
		{"unknown with a deny list", map[string]any{"deny": gpl}, pkg(), []string{license.IDUnknown}},
		{"unknown ignored with a deny list", map[string]any{"deny": gpl, "unknown": "ignore"}, pkg(), nil},
		{"none with a deny list", map[string]any{"deny": gpl}, pkg("NONE"), []string{license.IDUnknown}},
		{"none with an allow list", map[string]any{"allow": []any{"MIT"}}, pkg("NONE"), []string{license.IDNotAllowed}},
		{"unknown ignored on request", map[string]any{"allow": []any{"MIT"}, "unknown": "ignore"}, pkg(), nil},
		{"rejected part beside an unknown value", map[string]any{"allow": []any{"MIT"}}, pkg("GPL-3.0-only", "non-standard"), []string{license.IDNotAllowed}},
		{"rejected part beside an unknown value with unknown ignored", map[string]any{"allow": []any{"MIT"}, "unknown": "ignore"}, pkg("GPL-3.0-only", "non-standard"), []string{license.IDNotAllowed}},
		{"denied or-later with no later version", map[string]any{"deny": []any{"EUPL-1.2"}}, pkg("EUPL-1.2+"), []string{license.IDDenied}},
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
	assert.Equal(t, "pypi/pyqt5@5.15.11 has the denied license GPL-3.0-only", f.Title)
	require.Len(t, f.Evidence, 1)
	assert.Contains(t, f.Evidence[0].Summary, "The declared license is GPL-3.0, and its SPDX form is GPL-3.0-only. vet checks it with the SPDX License List ")
	assert.NotEmpty(t, f.Remediation.Summary)
}

func TestNoneTitle(t *testing.T) {
	c, err := license.New(plugin.MapConfig(map[string]any{"deny": []any{"GPL-3.0-only"}}))
	require.NoError(t, err)
	m := &model.Manifest{ID: "m", Path: "requirements.txt", Kind: model.ManifestKindManifest, Packages: []*model.Package{pkg("NONE")}}
	fs := plugintest.TestControl(t, c, m, nil)
	require.Len(t, fs, 1)
	assert.Equal(t, "pypi/pyqt5@5.15.11 declares no license, so the author keeps all rights", fs[0].Title)
}

func TestScope(t *testing.T) {
	gpl := func(name string, direct, dev bool) *model.Package {
		return &model.Package{
			ID: model.MustPackageVersion(model.EcosystemNpm, name, "1.0.0"), Direct: direct, Dev: dev,
			Insight: &model.Insight{Licenses: []string{"GPL-3.0-only"}},
		}
	}
	all := []*model.Package{gpl("runtime", true, false), gpl("dev", true, true), gpl("indirect", false, false)}
	cases := []struct {
		name  string
		scope string
		pkgs  []*model.Package
		want  []string
	}{
		{"default", "", all, []string{"runtime", "dev", "indirect"}},
		{"all", license.ScopeAll, all, []string{"runtime", "dev", "indirect"}},
		{"runtime", license.ScopeRuntime, all, []string{"runtime", "indirect"}},
		{"direct", license.ScopeDirect, all, []string{"runtime", "dev"}},
		{"direct with no direct data", license.ScopeDirect, []*model.Package{gpl("a", false, false), gpl("b", false, false)}, []string{"a", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := license.New(plugin.MapConfig(map[string]any{"deny": []any{"GPL-3.0-only"}, "scope": tc.scope}))
			require.NoError(t, err)
			m := &model.Manifest{ID: "m", Path: "package-lock.json", Kind: model.ManifestKindLockfile, Packages: tc.pkgs}
			var got []string
			for _, f := range plugintest.TestControl(t, c, m, nil) {
				got = append(got, f.Subject.Package.RawName)
			}
			assert.ElementsMatch(t, tc.want, got)
		})
	}
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
		{"a bad scope value", map[string]any{"scope": "prod"}, `license: scope "prod"`},
		{"an unknown option", map[string]any{"globs": true}, "globs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := license.New(plugin.MapConfig(tc.opts))
			assert.ErrorContains(t, err, tc.want)
		})
	}
}
