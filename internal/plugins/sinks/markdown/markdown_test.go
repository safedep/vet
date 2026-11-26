package markdown

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

func write(t *testing.T, r plugin.Report) string {
	t.Helper()
	sink, err := New(plugin.MapConfig(nil))
	require.NoError(t, err)
	var b bytes.Buffer
	require.NoError(t, sink.Write(context.Background(), r, &b))
	return b.String()
}

// section returns the text under a level 3 heading, up to the next one.
func section(out, heading string) string {
	_, rest, ok := strings.Cut(out, "### "+heading+"\n\n")
	if !ok {
		return ""
	}
	body, _, _ := strings.Cut(rest, "\n### ")
	return strings.TrimSpace(body)
}

func TestOneRowForEachCause(t *testing.T) {
	s := plugintest.UpgradeReport()
	s.FindingList[3].Change = model.ChangeAdded
	out := write(t, s)
	blocking := section(out, "Blocking findings (15)")
	assert.Equal(t, 1, strings.Count(blocking, "`npm/pnpm@12.15.0` and 14 more<br>`package.json:119` | upgraded, added |"),
		"one row for the release, with each change of its findings")
	assert.NotContains(t, blocking, "`npm/@pnpm/exe.linux-x64@12.15.0`", "a platform package has no row of its own")
	assert.Equal(t, "1. **Version inside the cooldown window (15 findings).** Keep \"packageManager\" at pnpm@12.8.2 in package.json. "+
		"Or wait until 2026-10-23 11:17 UTC, then run the job again.\n   - `npm/pnpm@12.15.0` and 14 more in `package.json:119`\n\n"+
		"**Policy help**\n\n- `package-cooldown`: Wait until the version is older than the cooldown, or pin an older version.",
		section(out, "What to do"))
	assert.NotContains(t, out, "### Causes")
}

// gated is a report of a go.mod with vulnerable modules, a file with a
// hidden payload and a workflow with a high finding that no rule blocks.
// The gate fails on the vulnerabilities and the payload. A medium
// vulnerability only warns.
func gated(outcome report.GateOutcome) *plugintest.MemState {
	a := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, "example.com/a", "1.0.0"), Line: 5, Insight: &model.Insight{LatestVersion: "1.3.0"}}
	old := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, "example.com/a", "0.9.0"), Line: 7}
	b := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, "example.com/b", "1.0.0"), Line: 6, Insight: &model.Insight{LatestVersion: "2.0.0"}}
	m := &model.Manifest{ID: "m-1", Path: "go.mod", Ecosystem: model.EcosystemGo, Kind: model.ManifestKindLockfile, Packages: []*model.Package{a, b, old}}
	rule := &finding.GateRecord{
		Action: finding.GateActionFail, Rules: []string{"no-high"},
		Help: "Upgrade the package to the fixed version.", Link: "https://wiki.example.com/vulns",
	}
	// vuln writes the remediation as the vulnerability control does.
	vuln := func(p *model.Package, id, fixed string, sev finding.Severity) *finding.Finding {
		f := finding.ForPackage(finding.Meta{
			ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: sev, Title: id + " in " + p.ID.String() + ": Bad | worse",
		}, m.Path, p, finding.Key{Discriminator: id})
		f.Advisory, f.References = id, []string{"https://osv.dev/vulnerability/" + id}
		f.Remediation = &finding.Remediation{Summary: fmt.Sprintf("Upgrade %s to %s or later.", p.ID.RawName(), fixed), FixedVersion: fixed}
		if fixed == "" {
			f.Remediation = &finding.Remediation{Summary: fmt.Sprintf("Upgrade %s to a version that fixes %s.", p.ID.RawName(), id)}
		}
		f.Gate = rule
		return &f
	}
	payload := finding.ForFile(finding.Meta{
		ControlID: "unicode-payload", Family: finding.FamilyHiddenCode, Severity: finding.SeverityCritical, Title: "The file hides a payload",
	}, finding.Locus{Path: "src/x.js", StartLine: 5}, finding.Key{})
	payload.Attack = &finding.Attack{Technique: "unicode-payload"}
	payload.Remediation = &finding.Remediation{Summary: "Do not run the code."}
	payload.Gate = &finding.GateRecord{Action: finding.GateActionFail, FailOn: "attacks"}
	trigger := finding.ForFile(finding.Meta{
		ControlID: "dangerous-trigger", Family: finding.FamilyWorkflow, Severity: finding.SeverityHigh, Title: "pull_request_target checks out the head",
	}, finding.Locus{Path: ".github/workflows/ci.yml", StartLine: 3}, finding.Key{})
	trigger.Remediation = &finding.Remediation{Summary: "Use pull_request."}
	warned := vuln(a, "GHSA-3", "", finding.SeverityMedium)
	warned.Gate = &finding.GateRecord{Action: finding.GateActionWarn, Rules: []string{"note-medium"}}

	s := plugintest.NewMemState(m)
	h := *s.Header()
	h.Controls = append(h.Controls,
		report.ControlName{ID: "unicode-payload", Title: "Payload in invisible Unicode characters"},
		report.ControlName{ID: "dangerous-trigger", Title: "Dangerous workflow trigger"})
	s.HeaderValue = &h
	s.FindingList = []*finding.Finding{
		vuln(a, "GHSA-1", "1.3.0", finding.SeverityHigh), vuln(a, "GHSA-2", "1.3.0", finding.SeverityHigh),
		vuln(a, "GHSA-5", "", finding.SeverityHigh), vuln(old, "GHSA-6", "1.1.0", finding.SeverityHigh),
		vuln(b, "GHSA-4", "", finding.SeverityCritical), &payload, &trigger, warned,
	}
	tr := *s.Trailer()
	tr.Gate = report.Gate{Outcome: outcome}
	if outcome == report.GateFail {
		tr.Gate.FailOn, tr.Gate.Rules = report.FailOnAttacks, []string{"no-high"}
		for _, f := range s.FindingList[:6] {
			tr.Gate.FindingIDs = append(tr.Gate.FindingIDs, f.ID)
		}
	}
	s.TrailerValue = &tr
	return s
}

func TestWhatToDo(t *testing.T) {
	out := write(t, gated(report.GateFail))
	assert.Equal(t, "1. **Payload in invisible Unicode characters (1 finding).** Do not run the code.\n"+
		"   - `src/x.js:5`\n"+
		"2. **In `go.mod`, upgrade 2 packages.** This can clear 5 findings.\n"+
		"   - `example.com/a` 1.0.0, 0.9.0 → **1.3.0** (4 findings, 1 with no known fixed version)\n"+
		"   - `example.com/b` 1.0.0 → **2.0.0**, the latest version (1 finding)\n\n"+
		"**Policy help**\n\n"+
		"- `no-high`: Upgrade the package to the fixed version. · [Policy guidance](https://wiki.example.com/vulns)",
		section(out, "What to do"), "only the blocking findings, attacks first, with each version in use and no claim that the fix is known")
}

func TestUpgradeClaim(t *testing.T) {
	s := gated(report.GateFail)
	s.FindingList = s.FindingList[:2]
	s.TrailerValue.Gate.FindingIDs = []string{s.FindingList[0].ID, s.FindingList[1].ID}
	assert.Contains(t, section(write(t, s), "What to do"),
		"**In `go.mod`, upgrade 1 package.** This clears 2 findings.\n   - `example.com/a` 1.0.0 → **1.3.0** (2 findings)",
		"each finding has a fixed version")
}

func TestWhatToDoWithNoBlockingFinding(t *testing.T) {
	for _, outcome := range []report.GateOutcome{report.GatePass, report.GateNone} {
		t.Run(string(outcome), func(t *testing.T) {
			todo := section(write(t, gated(outcome)), "What to do")
			assert.Contains(t, todo, "**Dangerous workflow trigger (1 finding).** Use pull\\_request.", "a finding to review has its fix")
			assert.Contains(t, todo, "**In `go.mod`, upgrade 2 packages.**")
		})
	}
}

func TestBlockingFindings(t *testing.T) {
	out := write(t, gated(report.GateFail))
	assert.Contains(t, out, "Policy rule no-high and --fail-on attacks block **6 findings** in this scan.")
	blocking := section(out, "Blocking findings (6)")
	assert.Contains(t, blocking, "| 🟠 high | [GHSA-1](https://osv.dev/vulnerability/GHSA-1) · `f-",
		"each advisory of one fix has its own row")
	assert.Contains(t, blocking, "| 🟠 high | [GHSA-2](https://osv.dev/vulnerability/GHSA-2) · `f-")
	assert.Contains(t, blocking, "<br>Bad \\| worse | `go/example.com/b@1.0.0`<br>`go.mod:6` | no-high |",
		"the row names the rule, and a pipe in the title does not split the cell")
	assert.NotContains(t, blocking, "GHSA-3", "a finding that only warns does not block")
	review := section(out, "Findings to review (1)")
	assert.Contains(t, review, "pull\\_request\\_target checks out the head", "a high finding that does not block stays open")
	other := section(out, "Other findings (1)")
	assert.Contains(t, other, "<details><summary><b>vulnerability</b> · 1 finding · 1 medium</summary>")
	assert.Contains(t, other, "Warned by policy rule note-medium", "a finding that warns names its rule")
}

func TestAnAttackThatDoesNotBlockStaysOpen(t *testing.T) {
	s := gated(report.GateFail)
	s.TrailerValue.Gate.FindingIDs = []string{s.FindingList[0].ID}
	out := write(t, s)
	assert.Contains(t, section(out, "Findings to review (6)"), "`src/x.js:5`")
	assert.NotContains(t, section(out, "What to do"), "src/x.js", "only the findings that block have a step")
}

func TestAnAttackWithAFixedVersionIsNoUpgrade(t *testing.T) {
	s := plugintest.SampleReport()
	malware := s.FindingList[0]
	malware.Remediation.FixedVersion = "1.5.0"
	tr := *s.Trailer()
	tr.Gate = report.Gate{Outcome: report.GateFail, FailOn: report.FailOnAttacks, FindingIDs: []string{malware.ID}}
	s.TrailerValue = &tr
	assert.Equal(t, "1. **Malicious package (1 finding).** Remove evil-colors.\n   - `npm/evil-colors@1.4.1` in `package-lock.json:42`",
		section(write(t, s), "What to do"))
}

func TestStatus(t *testing.T) {
	cases := []struct {
		name string
		edit func(s *plugintest.MemState)
		want string
	}{
		{
			name: "a rule that did not evaluate",
			edit: func(s *plugintest.MemState) {
				s.FindingList[0].Gate = &finding.GateRecord{Action: finding.GateActionFail, Broken: []string{"r"}}
				s.TrailerValue.Gate = report.Gate{Outcome: report.GateFail, FindingIDs: []string{s.FindingList[0].ID}}
			},
			want: "Policy rule r, which did not evaluate, blocks **1 finding** in this scan.",
		},
		{
			name: "suppressed findings",
			edit: func(s *plugintest.MemState) { s.TrailerValue.Summary.Suppressed = 3 },
			want: "The policy suppresses 3 more findings.",
		},
		{
			name: "a failed gate with no open finding that blocks",
			edit: func(s *plugintest.MemState) { s.TrailerValue.Gate = report.Gate{Outcome: report.GateFail} },
			want: "The gate failed. No open finding blocks it.",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := plugintest.SampleReport()
			s.Trailer()
			tc.edit(s)
			assert.Contains(t, write(t, s), tc.want)
		})
	}
}

func TestUntrustedText(t *testing.T) {
	s := plugintest.SampleReport()
	s.FindingList[1].ControlID = "c</summary><img src=x>@octocat"
	s.FindingList[2].Suppression.Reason = "see [x](https://evil.example) @octocat"
	out := write(t, s)
	assert.Contains(t, out, "<summary><b>c&lt;/summary&gt;&lt;img src=x&gt;@\u200boctocat</b>", "a control id cannot close the summary")
	assert.Contains(t, out, `: see \[x\](https:`+"\u200b"+`//evil.example) @`+"\u200b"+`octocat`, "a suppression reason cannot link or mention")
}

func TestBounds(t *testing.T) {
	m := &model.Manifest{ID: "m-1", Path: "go.mod", Ecosystem: model.EcosystemGo, Kind: model.ManifestKindLockfile}
	s := plugintest.NewMemState(m)
	var ids []string
	for i := range 60 {
		p := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, fmt.Sprintf("example.com/p%02d", i), "1.0.0")}
		m.Packages = append(m.Packages, p)
		f := finding.ForPackage(finding.Meta{ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: finding.SeverityHigh, Title: "v"},
			m.Path, p, finding.Key{})
		f.Advisory = fmt.Sprintf("GHSA-%02d", i)
		f.Remediation = &finding.Remediation{Summary: "Upgrade.", FixedVersion: "1.1.0"}
		f.Gate = &finding.GateRecord{Action: finding.GateActionFail, Rules: []string{"r"}}
		s.FindingList = append(s.FindingList, &f)
		ids = append(ids, f.ID)
		low := finding.ForPackage(finding.Meta{ControlID: "scorecard-low", Family: finding.FamilyHygiene, Severity: finding.SeverityInfo, Title: "low"},
			m.Path, p, finding.Key{})
		s.FindingList = append(s.FindingList, &low)
	}
	for i := range 7 {
		f := finding.ForFile(finding.Meta{ControlID: "agent-hook-command", Family: finding.FamilyAgentConfig, Severity: finding.SeverityHigh, Title: "hook"},
			finding.Locus{Path: fmt.Sprintf("hook%d.yml", i), StartLine: 1}, finding.Key{})
		f.Remediation = &finding.Remediation{Summary: "Review the command."}
		f.Gate = &finding.GateRecord{Action: finding.GateActionFail, Rules: []string{"r"}}
		s.FindingList = append(s.FindingList, &f)
		ids = append(ids, f.ID)
	}
	s.Trailer().Gate = report.Gate{Outcome: report.GateFail, FindingIDs: ids}
	out := write(t, s)
	todo := section(out, "What to do")
	assert.Contains(t, todo, "   - 10 more in the full report\n", "an upgrade step lists at most 50 packages")
	assert.True(t, strings.HasSuffix(todo, "\n   - 2 more"), "a step lists at most 5 places")
	assert.Equal(t, 50, strings.Count(section(out, "Blocking findings (67)"), "| 🟠 high |"), "a table has at most 50 rows")
	assert.Contains(t, section(out, "Blocking findings (67)"), "The full report has 17 more.")
	assert.Contains(t, out, "The full report has 10 more.\n\n</details>", "a control list has at most 50 rows")
}

func TestStepsBeyondTheLimit(t *testing.T) {
	s := plugintest.NewMemState()
	var ids []string
	for i := range 12 {
		f := finding.ForFile(finding.Meta{ControlID: fmt.Sprintf("c%02d", i), Family: finding.FamilyWorkflow, Severity: finding.SeverityHigh, Title: "t"},
			finding.Locus{Path: "a.yml", StartLine: i + 1}, finding.Key{})
		f.Gate = &finding.GateRecord{Action: finding.GateActionFail, Rules: []string{"r"}}
		s.FindingList = append(s.FindingList, &f)
		ids = append(ids, f.ID)
	}
	s.Trailer().Gate = report.Gate{Outcome: report.GateFail, FindingIDs: ids}
	todo := section(write(t, s), "What to do")
	assert.Equal(t, 10, strings.Count(todo, "(1 finding).**"), "the list has at most 10 steps")
	assert.True(t, strings.HasSuffix(todo, "This list leaves out 2 more steps. The tables show their findings."))
}

func TestShortIDsTellSuppressedFindingsApart(t *testing.T) {
	s := plugintest.SampleReport()
	s.FindingList[0].ID = "f-aaaaaaaa11"
	s.FindingList[2].ID = "f-aaaaaaaa22"
	out := write(t, s)
	require.NotNil(t, s.FindingList[2].Suppression)
	assert.Contains(t, out, "`f-aaaaaaaa1`", "the short id of an open finding does not match a suppressed finding")
	assert.NotContains(t, out, "`f-aaaaaaaa`")
}

func TestTheRowLimitKeepsTheMostSevereAdvisories(t *testing.T) {
	m := &model.Manifest{ID: "m-1", Path: "go.mod", Ecosystem: model.EcosystemGo, Kind: model.ManifestKindLockfile}
	s := plugintest.NewMemState(m)
	var ids []string
	add := func(name string, sev finding.Severity) {
		p := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, name, "1.0.0")}
		m.Packages = append(m.Packages, p)
		f := finding.ForPackage(finding.Meta{ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: sev, Title: "v"}, m.Path, p, finding.Key{})
		f.Advisory = "GHSA-" + name
		f.Remediation = &finding.Remediation{Summary: "Upgrade."}
		f.Gate = &finding.GateRecord{Action: finding.GateActionFail, Rules: []string{"r"}}
		s.FindingList = append(s.FindingList, &f)
		ids = append(ids, f.ID)
	}
	for i := range 60 {
		add(fmt.Sprintf("p%02d", i), finding.SeverityHigh)
	}
	add("zz00", finding.SeverityCritical)
	add("zz01", finding.SeverityCritical)
	s.Trailer().Gate = report.Gate{Outcome: report.GateFail, FindingIDs: ids}
	blocking := section(write(t, s), "Blocking findings (62)")
	assert.Contains(t, blocking, "GHSA-zz00")
	assert.Contains(t, blocking, "GHSA-zz01")
	assert.Equal(t, 2, strings.Count(blocking, "| 🔴 critical |"))
}
