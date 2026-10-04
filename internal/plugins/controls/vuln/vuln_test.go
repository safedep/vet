package vuln

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

func manifest(in *model.Insight) *model.Manifest {
	return &model.Manifest{
		ID: "m1", Path: "requirements.txt", Ecosystem: model.EcosystemPyPI, Kind: model.ManifestKindManifest,
		Packages: []*model.Package{{
			ID:      model.MustPackageVersion(model.EcosystemPyPI, "requests", "2.0.0"),
			Direct:  true,
			Insight: in,
		}},
	}
}

func TestEvaluate(t *testing.T) {
	cases := []struct {
		name     string
		vuln     model.Vulnerability
		latest   string
		wantSev  finding.Severity
		wantConf finding.Confidence
		wantFix  string
		wantText string
	}{
		{name: "risk", vuln: model.Vulnerability{ID: "GHSA-1", Severity: "critical", CVSS: 5}, wantSev: finding.SeverityCritical, wantConf: finding.ConfidenceHigh, wantText: "fixes GHSA-1."},
		{name: "cvss high", vuln: model.Vulnerability{ID: "GHSA-2", CVSS: 7.5}, wantSev: finding.SeverityHigh, wantConf: finding.ConfidenceHigh, wantText: "fixes GHSA-2."},
		{name: "cvss low", vuln: model.Vulnerability{ID: "GHSA-3", CVSS: 2}, wantSev: finding.SeverityLow, wantConf: finding.ConfidenceHigh},
		{name: "no severity", vuln: model.Vulnerability{ID: "GHSA-4"}, wantSev: finding.SeverityMedium, wantConf: finding.ConfidenceLow},
		{name: "fixed version", vuln: model.Vulnerability{ID: "GHSA-5", Severity: "high", Fixed: []string{"2.0.1"}}, wantSev: finding.SeverityHigh, wantConf: finding.ConfidenceHigh, wantFix: "2.0.1", wantText: "to 2.0.1 or later"},
		{name: "latest version", vuln: model.Vulnerability{ID: "GHSA-6", Severity: "medium"}, latest: "2.32.0", wantSev: finding.SeverityMedium, wantConf: finding.ConfidenceHigh, wantText: "The latest version is 2.32.0."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(plugin.MapConfig(nil))
			require.NoError(t, err)
			fs := plugintest.TestControl(t, c, manifest(&model.Insight{Vulnerabilities: []model.Vulnerability{tc.vuln}, LatestVersion: tc.latest}), nil)
			require.Len(t, fs, 1)
			f := fs[0]
			assert.Equal(t, Name, f.ControlID)
			assert.Equal(t, tc.wantSev, f.Severity)
			assert.Equal(t, tc.wantConf, f.Confidence)
			assert.Contains(t, f.Title, tc.vuln.ID)
			assert.Equal(t, []string{"https://osv.dev/vulnerability/" + tc.vuln.ID}, f.References)
			require.NotNil(t, f.Remediation)
			assert.Equal(t, tc.wantFix, f.Remediation.FixedVersion)
			assert.Contains(t, f.Remediation.Summary, tc.wantText)
		})
	}
}

func TestOneFindingForEachAdvisory(t *testing.T) {
	c, err := New(plugin.MapConfig(nil))
	require.NoError(t, err)
	fs := plugintest.TestControl(t, c, manifest(&model.Insight{Vulnerabilities: []model.Vulnerability{
		{ID: "GHSA-a", Severity: "high"}, {ID: "GHSA-b", Severity: "low"},
	}}), nil)
	require.Len(t, fs, 2)
	assert.NotEqual(t, fs[0].ID, fs[1].ID)

	none := plugintest.TestControl(t, c, manifest(nil), nil)
	assert.Empty(t, none, "a package with no data gives no finding")
}

func TestNewRejectsOptions(t *testing.T) {
	_, err := New(plugin.MapConfig{"min_severity": "high"})
	assert.Error(t, err)
}
