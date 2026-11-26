package overview

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

func TestRead(t *testing.T) {
	s := plugintest.SampleReport()
	s.ManifestList[0].Packages[0].Change = model.ChangeAdded
	s.ManifestList[0].Packages[1].Insight = &model.Insight{LatestVersion: "1.3.1"}
	s.ManifestList = append(s.ManifestList, &model.Manifest{ID: "w", Path: ".github/workflows/ci.yml", Kind: model.ManifestKindWorkflow, Change: model.ChangeModified})
	pad := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "left-pad", "1.3.0")}
	vuln := finding.ForPackage(finding.Meta{
		ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: finding.SeverityHigh, Title: "GHSA-1",
	}, "package-lock.json", pad, finding.Key{Discriminator: "GHSA-1"})
	s.FindingList = append(s.FindingList, &vuln)
	got, err := Read(context.Background(), s)
	require.NoError(t, err)
	assert.Equal(t, Changes{Packages: 1, Workflows: 1, Unchanged: 1}, got.Changes)
	assert.Len(t, got.Diagnostics, 1)
	assert.Len(t, got.Suppressed, 1)
	assert.Equal(t, map[model.PackageKey]string{model.MustPackageVersion(model.EcosystemNpm, "left-pad", "1.3.0").Key(): "1.3.1"}, got.Latest)
	var severities []finding.Severity
	for _, f := range got.Findings {
		severities = append(severities, f.Severity)
	}
	assert.Equal(t, []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium}, severities,
		"the most severe first, and no suppressed finding")
}

func TestUpgrades(t *testing.T) {
	pkg := func(version, fixed string) *finding.Finding {
		p := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "a", version)}
		f := finding.ForPackage(finding.Meta{ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: finding.SeverityHigh, Title: "v"},
			"package-lock.json", p, finding.Key{Discriminator: version + fixed})
		f.Remediation = &finding.Remediation{Summary: "Upgrade.", FixedVersion: fixed}
		return &f
	}
	latest := map[model.PackageKey]string{
		model.MustPackageVersion(model.EcosystemNpm, "a", "1.0.0").Key(): "1.5.0",
		model.MustPackageVersion(model.EcosystemNpm, "a", "0.9.0").Key(): "1.5.0",
	}
	cases := []struct {
		name        string
		findings    []*finding.Finding
		want        string
		wantLatest  bool
		wantUnfixed int
		wantFrom    []string
	}{
		{name: "a fixed version above the latest version", findings: []*finding.Finding{pkg("1.0.0", ""), pkg("1.0.0", "2.0.0")}, want: "2.0.0", wantUnfixed: 1, wantFrom: []string{"1.0.0"}},
		{name: "the latest version above a fixed version", findings: []*finding.Finding{pkg("1.0.0", "1.2.0"), pkg("1.0.0", "")}, want: "1.5.0", wantLatest: true, wantUnfixed: 1, wantFrom: []string{"1.0.0"}},
		{name: "a fixed version that is the latest version", findings: []*finding.Finding{pkg("1.0.0", ""), pkg("1.0.0", "1.5.0")}, want: "1.5.0", wantUnfixed: 1, wantFrom: []string{"1.0.0"}},
		{name: "two versions in use", findings: []*finding.Finding{pkg("1.0.0", "1.2.0"), pkg("0.9.0", "1.1.0")}, want: "1.2.0", wantFrom: []string{"1.0.0", "0.9.0"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ups := Upgrades(tc.findings, latest)
			require.Len(t, ups, 1)
			u := ups[0]
			assert.Equal(t, tc.want, u.To.RawVersion())
			assert.Equal(t, tc.wantLatest, u.Latest)
			assert.Equal(t, tc.wantUnfixed, u.Unfixed)
			var from []string
			for _, v := range u.From {
				from = append(from, v.RawVersion())
			}
			assert.Equal(t, tc.wantFrom, from)
			assert.Len(t, u.Findings, 2, "each finding of the package is in the upgrade")
		})
	}
}

func TestSections(t *testing.T) {
	f := func(id string, sev finding.Severity, attack bool) *finding.Finding {
		x := finding.ForFile(finding.Meta{ControlID: "c", Family: finding.FamilyWorkflow, Severity: sev, Title: id}, finding.Locus{Path: id}, finding.Key{})
		x.ID = id
		if attack {
			x.Attack = &finding.Attack{Technique: "t"}
		}
		return &x
	}
	s := Overview{Findings: []*finding.Finding{
		f("block", finding.SeverityHigh, false), f("attack", finding.SeverityLow, true),
		f("high", finding.SeverityHigh, false), f("low", finding.SeverityLow, false),
	}}
	sec := s.Sections(report.Gate{Outcome: report.GateFail, FindingIDs: []string{"block"}})
	ids := func(fs []*finding.Finding) []string {
		var out []string
		for _, f := range fs {
			out = append(out, f.ID)
		}
		return out
	}
	assert.Equal(t, []string{"block"}, ids(sec.Blocking))
	assert.Equal(t, []string{"attack"}, ids(sec.Attacks))
	assert.Equal(t, []string{"high"}, ids(sec.Review))
	assert.Equal(t, []string{"low"}, ids(sec.Rest))
	assert.Empty(t, s.Sections(report.Gate{Outcome: report.GatePass, FindingIDs: []string{"block"}}).Blocking, "a gate that passes blocks nothing")
}
