package prcomment

import (
	"regexp"
	"slices"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/policy"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

var snippetYAML = regexp.MustCompile("(?s)```yaml\n(suppressions:\n.*?)```")

// suppressed loads the snippet of the comment with the policy loader, and
// returns the ids of the findings of s that it suppresses at now.
func suppressed(t *testing.T, s *plugintest.MemState, now time.Time) []string {
	t.Helper()
	m := snippetYAML.FindStringSubmatch(newInput(t, s).body())
	require.Len(t, m, 2, "the comment has a snippet")
	p, err := policy.Parse("policy.yml", []byte("version: 2\n"+m[1]))
	require.NoError(t, err)
	e := policy.NewEvaluator(p, policy.Options{Now: func() time.Time { return now }})
	var ids []string
	for _, f := range s.FindingList {
		c := *f
		e.Apply(&c, nil, nil)
		if c.Suppressed() {
			ids = append(ids, c.ID)
		}
	}
	return ids
}

func TestSnippetSuppressesTheGroupAndNoOtherFinding(t *testing.T) {
	s := plugintest.UpgradeReport()
	before := time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC)
	got := suppressed(t, s, before)
	slices.Sort(got)
	want := slices.Clone(s.TrailerValue.Gate.FindingIDs)
	slices.Sort(want)
	assert.Equal(t, want, got)

	after := time.Date(2026, 10, 24, 0, 0, 0, 0, time.UTC)
	assert.Empty(t, suppressed(t, s, after), "the suppression ends with the cooldown")
}

// A glob that also matches a finding of the control outside the group
// would hide it, so the snippet names each package.
func TestSnippetGlobFallsBackToNames(t *testing.T) {
	s := plugintest.UpgradeReport()
	m := s.ManifestList[0]
	p := &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, "@pnpm/exe.haiku-x64", "12.15.0"), Change: model.ChangeAdded}
	m.Packages = append(m.Packages, p)
	other := finding.ForPackage(finding.Meta{
		ControlID: "dependency-cooldown", Family: finding.FamilyCooldown, Severity: finding.SeverityHigh, Title: "Published 1 day ago",
	}, m.Path, p, finding.Key{})
	other.Remediation = &finding.Remediation{Summary: "Keep the version that you used before, or wait until 2026-10-23."}
	s.FindingList = append(s.FindingList, &other)

	got := suppressed(t, s, time.Date(2026, 10, 22, 0, 0, 0, 0, time.UTC))
	assert.NotContains(t, got, other.ID)
	assert.Len(t, got, len(s.TrailerValue.Gate.FindingIDs))
}

func TestSnippetOfAnAttackNamesTheFinding(t *testing.T) {
	s := pullRequest(report.GateFail)
	got := suppressed(t, s, time.Now())
	assert.Equal(t, []string{s.FindingList[0].ID}, got)
}

func TestStem(t *testing.T) {
	cases := map[string]string{
		"@pnpm/exe.linux-x64":          "@pnpm/exe.",
		"pnpm":                         "pnpm",
		"lefthook-android-arm64":       "lefthook-",
		"github.com/acme/sdk_go":       "github.com/acme/sdk_",
		"@esbuild/linux-x64":           "@esbuild/linux-",
		"buf.build/gen/go/acme/api.v2": "buf.build/gen/go/acme/api.",
	}
	for name, want := range cases {
		assert.Equal(t, want, stem(name), name)
	}
}

// A second advisory of the same package has another fix, so it is not in
// the group. An entry by PURL and control would hide it.
func TestSnippetOfOnePackageWithTwoAdvisories(t *testing.T) {
	s := pullRequest(report.GateFail)
	pad := s.ManifestList[0].Packages[1]
	vuln := func(adv, fix string, sev finding.Severity) *finding.Finding {
		f := finding.ForPackage(finding.Meta{ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: sev, Title: adv},
			"package-lock.json", pad, finding.Key{Discriminator: adv})
		f.Remediation = &finding.Remediation{Summary: fix}
		return &f
	}
	high, low := vuln("GHSA-1", "Upgrade left-pad to 1.3.1 or later.", finding.SeverityHigh), vuln("GHSA-2", "Upgrade left-pad to 2.0.0 or later.", finding.SeverityLow)
	s.FindingList = append(s.FindingList, high, low)
	s.TrailerValue.Gate.Outcome = report.GatePass
	s.FindingList[0].Attack = nil
	s.FindingList[0].Severity = finding.SeverityLow

	got := suppressed(t, s, time.Now())
	assert.Equal(t, []string{high.ID}, got)
}
