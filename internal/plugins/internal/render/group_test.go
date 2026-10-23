package render

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

func pkgFinding(id, control, name string, sev finding.Severity, fix string) *finding.Finding {
	f := finding.ForPackage(finding.Meta{ControlID: control, Severity: sev, Title: id},
		"package-lock.json", &model.Package{ID: model.MustPackageVersion(model.EcosystemNpm, name, "1.0.0")}, finding.Key{})
	f.ID = id
	if fix != "" {
		f.Remediation = &finding.Remediation{Summary: fix}
	}
	return &f
}

func ids(g Group) []string {
	var out []string
	for _, f := range g.Findings {
		out = append(out, f.ID)
	}
	return out
}

func TestGroups(t *testing.T) {
	exe := pkgFinding("1", "cooldown", "@pnpm/exe.linux-x64", finding.SeverityHigh, "Keep 1.0.0.")
	main := pkgFinding("2", "cooldown", "pnpm", finding.SeverityHigh, "Keep 1.0.0.")
	other := pkgFinding("3", "cooldown", "left-pad", finding.SeverityHigh, "Keep 0.9.0.")
	nofix := pkgFinding("4", "hygiene", "a", finding.SeverityMedium, "")
	nofix2 := pkgFinding("5", "hygiene", "b", finding.SeverityMedium, "")
	attack := pkgFinding("6", "malware", "evil", finding.SeverityCritical, "Remove the package.")
	attack.Attack = &finding.Attack{Technique: "malicious-package"}
	attack2 := pkgFinding("7", "malware", "evil2", finding.SeverityCritical, "Remove the package.")
	attack2.Attack = attack.Attack
	gated := pkgFinding("8", "cooldown", "pnpm-extra", finding.SeverityHigh, "Keep 1.0.0.")
	gated.Gate = &finding.GateRecord{Action: finding.GateActionFail, Rules: []string{"r"}}

	got := Groups([]*finding.Finding{exe, main, other, nofix, nofix2, attack, attack2, gated})
	var all [][]string
	for _, g := range got {
		all = append(all, ids(g))
	}
	assert.Equal(t, [][]string{{"6"}, {"7"}, {"2", "1"}, {"3"}, {"8"}, {"4"}, {"5"}}, all,
		"attacks first and never folded, then by severity and size; the shortest name leads; a finding with no fix or another gate record stays apart")
}

func TestLeadIsTheDirectDependency(t *testing.T) {
	short := pkgFinding("1", "c", "ab", finding.SeverityHigh, "fix")
	direct := pkgFinding("2", "c", "abcdef", finding.SeverityHigh, "fix")
	direct.Subject.Package.Direct = true
	g := Groups([]*finding.Finding{short, direct})
	require.Len(t, g, 1)
	assert.Equal(t, "2", g[0].Lead().ID)
	assert.Equal(t, " and 1 more", g[0].More())
}

func TestGroupSeverityAndWait(t *testing.T) {
	a := pkgFinding("1", "c", "a", finding.SeverityMedium, "fix")
	b := pkgFinding("2", "c", "b", finding.SeverityHigh, "fix")
	early, late := time.Date(2026, 10, 23, 11, 15, 0, 0, time.UTC), time.Date(2026, 10, 23, 11, 16, 31, 0, time.UTC)
	a.Remediation.WaitUntil, b.Remediation.WaitUntil = &late, &early
	g := Groups([]*finding.Finding{a, b})
	require.Len(t, g, 1)
	assert.Equal(t, finding.SeverityHigh, g[0].Severity())
	until, ok := g[0].WaitUntil()
	assert.True(t, ok)
	assert.Equal(t, late, until, "the group waits for its last finding")
}

// A lead of lower severity cannot hide a severe finding of its group.
func TestGroupKind(t *testing.T) {
	medium := pkgFinding("1", "c", "a", finding.SeverityMedium, "fix")
	medium.Subject.Package.Direct = true
	high := pkgFinding("2", "c", "bb", finding.SeverityHigh, "fix")
	g := Groups([]*finding.Finding{medium, high})
	require.Len(t, g, 1)
	require.Equal(t, "1", g[0].Lead().ID)
	assert.Equal(t, "high", g[0].Kind())

	cooldown := pkgFinding("3", "c", "a", finding.SeverityHigh, "fix")
	cooldown.Family = finding.FamilyCooldown
	assert.Equal(t, "cooldown", Groups([]*finding.Finding{cooldown})[0].Kind())
}
