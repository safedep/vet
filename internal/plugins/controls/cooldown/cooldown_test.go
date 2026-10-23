package cooldown

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

var now = time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)

func pkg(name string, published *time.Time) *model.Package {
	p := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, name, "1.0.0"), Direct: true}
	if published != nil {
		p.Insight = &model.Insight{PublishedAt: published}
	}
	return p
}

func at(d time.Duration) *time.Time {
	t := now.Add(-d)
	return &t
}

func TestEvaluate(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		name    string
		options plugin.MapConfig
		pkg     *model.Package
		want    string
	}{
		{name: "published today", pkg: pkg("a", at(2*time.Hour)), want: "Published less than 1 day ago"},
		{name: "published 1 day ago", pkg: pkg("a", at(1*day+23*time.Hour)), want: "Published 1 day ago"},
		{name: "published 2 days ago", pkg: pkg("a", at(2*day))},
		{name: "published long ago", pkg: pkg("a", at(400*day))},
		{name: "no publish date", pkg: pkg("a", nil)},
		{name: "a wider window", options: plugin.MapConfig{"days": 30}, pkg: pkg("a", at(20*day)), want: "Published 20 days ago"},
		{name: "a narrower window", options: plugin.MapConfig{"days": 1}, pkg: pkg("a", at(30*time.Hour))},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(tc.options)
			require.NoError(t, err)
			c.(*Control).now = func() time.Time { return now }
			m := &model.Manifest{ID: "m1", Path: "package-lock.json", Ecosystem: model.EcosystemNpm, Kind: model.ManifestKindLockfile, Packages: []*model.Package{tc.pkg}}
			fs := plugintest.TestControl(t, c, m, nil)
			if tc.want == "" {
				assert.Empty(t, fs)
				return
			}
			require.Len(t, fs, 1)
			assert.Equal(t, Name, fs[0].ControlID)
			assert.Equal(t, tc.want, fs[0].Title)
			assert.Contains(t, fs[0].Description, "The version can merge after")
		})
	}
}

func TestRemediationNamesThePreviousVersion(t *testing.T) {
	c, err := New(plugin.MapConfig(nil))
	require.NoError(t, err)
	c.(*Control).now = func() time.Time { return now }
	p := pkg("a", at(time.Hour))
	p.Change, p.PreviousVersion = model.ChangeUpgraded, "0.9.0"
	fs := plugintest.TestControl(t, c, &model.Manifest{ID: "m1", Path: "package-lock.json", Packages: []*model.Package{p}}, nil)
	require.Len(t, fs, 1)
	assert.Equal(t, "Keep version 0.9.0, or wait until 2026-10-04.", fs[0].Remediation.Summary)
	assert.Equal(t, now.Add(-time.Hour).AddDate(0, 0, DefaultDays), *fs[0].Remediation.WaitUntil)
	assert.Equal(t, model.ChangeUpgraded, fs[0].Change)
}

// origins is a config with the source of each option.
type origins struct {
	plugin.MapConfig
	from map[string]string
}

func (o origins) Origin(key string) string { return o.from[key] }

func TestDescriptionNamesTheWindowAndItsSource(t *testing.T) {
	cases := []struct {
		name string
		cfg  plugin.Config
		want string
	}{
		{"default", plugin.MapConfig(nil), "The cooldown is 2 days (vet default). The version can merge after 2026-10-04 11:00 UTC."},
		{"flag", origins{plugin.MapConfig{"days": 5}, map[string]string{"days": "flag --cooldown-days"}}, "The cooldown is 5 days (flag --cooldown-days). The version can merge after 2026-10-07 11:00 UTC."},
		{"config with no source", plugin.MapConfig{"days": 1}, "The cooldown is 1 day (your config)."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(tc.cfg)
			require.NoError(t, err)
			c.(*Control).now = func() time.Time { return now }
			fs := plugintest.TestControl(t, c, &model.Manifest{ID: "m1", Path: "package-lock.json", Packages: []*model.Package{pkg("a", at(time.Hour))}}, nil)
			require.Len(t, fs, 1)
			assert.Contains(t, fs[0].Description, tc.want)
		})
	}
}

func TestSkip(t *testing.T) {
	c, err := New(plugin.MapConfig{"skip": []any{
		map[string]any{"purl": "pkg:golang/buf.build/gen/go/safedep/*", "reason": "Our own SDK."},
		map[string]any{"purl": "pkg:npm/left-pad@1.0.0", "reason": "Reviewed."},
	}})
	require.NoError(t, err)
	c.(*Control).now = func() time.Time { return now }
	goPkg := func(name string) *model.Package {
		p := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, name, "v1.0.0")}
		p.Insight = &model.Insight{PublishedAt: at(time.Hour)}
		return p
	}
	sdk, other := goPkg("buf.build/gen/go/safedep/api/grpc/go"), goPkg("buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go")
	fs := plugintest.TestControl(t, c, &model.Manifest{ID: "m1", Path: "go.mod", Packages: []*model.Package{sdk, other, pkg("left-pad", at(time.Hour))}}, nil)
	require.Len(t, fs, 1)
	assert.Contains(t, fs[0].Subject.Package.PURL, "protovalidate")
}

func TestNewRejectsBadSkip(t *testing.T) {
	cases := []struct {
		name string
		skip map[string]any
		want string
	}{
		{"no reason", map[string]any{"purl": "pkg:npm/a"}, "skip[0]: reason is empty"},
		{"not a PURL", map[string]any{"purl": "not a purl", "reason": "r"}, "skip[0]"},
		{"a glob that does not parse", map[string]any{"purl": "pkg:npm/a[", "reason": "r"}, "name glob"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(plugin.MapConfig{"skip": []any{tc.skip}})
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestNewRejectsBadDays(t *testing.T) {
	for _, opts := range []plugin.MapConfig{{"days": 0}, {"days": "five"}, {"window": 5}} {
		_, err := New(opts)
		assert.Error(t, err, "%v", opts)
	}
}

// pnpm and the packages that it installs for itself share the
// "packageManager" field, so they share one fix and one place.
func TestFixOfAPackageManagerRelease(t *testing.T) {
	c, err := New(plugin.MapConfig(nil))
	require.NoError(t, err)
	c.(*Control).now = func() time.Time { return now }
	decl := &model.Declaration{Path: "package.json", Line: 119, Field: "packageManager", Package: "pnpm"}
	pnpm, exe := pkg("pnpm", at(time.Hour)), pkg("@pnpm/exe.linux-x64", at(time.Hour))
	for _, p := range []*model.Package{pnpm, exe} {
		p.Change, p.PreviousVersion, p.Declared = model.ChangeUpgraded, "0.9.0", decl
	}
	fs := plugintest.TestControl(t, c, &model.Manifest{ID: "m1", Path: "pnpm-lock.yaml", Packages: []*model.Package{pnpm, exe}}, nil)
	require.Len(t, fs, 2)
	for _, f := range fs {
		assert.Equal(t, `Keep "packageManager" at pnpm@0.9.0 in package.json, or wait until 2026-10-04.`, f.Remediation.Summary)
		assert.Equal(t, &finding.Locus{Path: "package.json", StartLine: 119}, f.Locus)
	}
}
