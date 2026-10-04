package cooldown

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
		{name: "published today", pkg: pkg("a", at(2*time.Hour)), want: "npm/a@1.0.0 was published less than 1 day ago"},
		{name: "published 4 days ago", pkg: pkg("a", at(4*day+23*time.Hour)), want: "npm/a@1.0.0 was published 4 days ago"},
		{name: "published 5 days ago", pkg: pkg("a", at(5*day))},
		{name: "published long ago", pkg: pkg("a", at(400*day))},
		{name: "no publish date", pkg: pkg("a", nil)},
		{name: "a wider window", options: plugin.MapConfig{"days": 30}, pkg: pkg("a", at(20*day)), want: "npm/a@1.0.0 was published 20 days ago"},
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
			assert.Contains(t, fs[0].Description, "eligible on")
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
	assert.Contains(t, fs[0].Remediation.Summary, "keep version 0.9.0")
	assert.Equal(t, model.ChangeUpgraded, fs[0].Change)
}

func TestNewRejectsBadDays(t *testing.T) {
	for _, opts := range []plugin.MapConfig{{"days": 0}, {"days": "five"}, {"window": 5}} {
		_, err := New(opts)
		assert.Error(t, err, "%v", opts)
	}
}
