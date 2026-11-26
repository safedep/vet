package markdown

import (
	"bytes"
	"context"
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
	out := write(t, plugintest.UpgradeReport())
	blocking := section(out, "Blocking findings (15)")
	assert.Equal(t, 1, strings.Count(blocking, "`npm/pnpm@12.15.0` and 14 more<br>`package.json:119`"), "one row for the release")
	assert.NotContains(t, blocking, "`npm/@pnpm/exe.linux-x64@12.15.0`", "a platform package has no row of its own")
	assert.Equal(t, "1. **Version inside the cooldown window (15 findings).** Keep \"packageManager\" at pnpm@12.8.2 in package.json. "+
		"Or wait until 2026-10-23 11:17 UTC, then run the job again.\n   - `npm/pnpm@12.15.0` and 14 more in `package.json:119`",
		section(out, "What to do"))
	assert.NotContains(t, out, "### Causes")
}

// gated is a report of a go.mod with two vulnerable modules and a file with
// a hidden payload. The gate fails on each of them, and a medium
// vulnerability only warns.
func gated(outcome report.GateOutcome) *plugintest.MemState {
	a := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, "example.com/a", "1.0.0"), Line: 5}
	b := &model.Package{ID: model.MustPackageVersion(model.EcosystemGo, "example.com/b", "1.0.0"), Line: 6, Insight: &model.Insight{LatestVersion: "2.0.0"}}
	m := &model.Manifest{ID: "m-1", Path: "go.mod", Ecosystem: model.EcosystemGo, Kind: model.ManifestKindLockfile, Packages: []*model.Package{a, b}}
	rule := &finding.GateRecord{Action: finding.GateActionFail, Rules: []string{"no-high"}}
	vuln := func(p *model.Package, id, fixed string, sev finding.Severity) *finding.Finding {
		f := finding.ForPackage(finding.Meta{
			ControlID: "vulnerability", Family: finding.FamilyVulnerability, Severity: sev, Title: id + " in " + p.ID.String() + ": Bad | worse",
		}, m.Path, p, finding.Key{Discriminator: id})
		f.Advisory, f.References = id, []string{"https://osv.dev/vulnerability/" + id}
		f.Remediation = &finding.Remediation{Summary: "Upgrade to fix " + id + ".", FixedVersion: fixed}
		f.Gate = rule
		return &f
	}
	payload := finding.ForFile(finding.Meta{
		ControlID: "unicode-payload", Family: finding.FamilyHiddenCode, Severity: finding.SeverityCritical, Title: "The file hides a payload",
	}, finding.Locus{Path: "src/x.js", StartLine: 5}, finding.Key{})
	payload.Attack = &finding.Attack{Technique: "unicode-payload"}
	payload.Remediation = &finding.Remediation{Summary: "Do not run the code."}
	payload.Gate = &finding.GateRecord{Action: finding.GateActionFail, FailOn: "attacks"}
	warned := vuln(a, "GHSA-3", "", finding.SeverityMedium)
	warned.Gate = &finding.GateRecord{Action: finding.GateActionWarn, Rules: []string{"note-medium"}}

	s := plugintest.NewMemState(m)
	h := *s.Header()
	h.Controls = append(h.Controls, report.ControlName{ID: "unicode-payload", Title: "Payload in invisible Unicode characters"})
	s.HeaderValue = &h
	s.FindingList = []*finding.Finding{
		vuln(a, "GHSA-1", "1.2.6", finding.SeverityHigh), vuln(a, "GHSA-2", "1.3.0", finding.SeverityHigh),
		vuln(b, "GHSA-4", "", finding.SeverityCritical), &payload, warned,
	}
	tr := *s.Trailer()
	tr.Gate = report.Gate{Outcome: outcome}
	if outcome == report.GateFail {
		tr.Gate.FailOn, tr.Gate.Rules = report.FailOnAttacks, []string{"no-high"}
		for _, f := range s.FindingList[:4] {
			tr.Gate.FindingIDs = append(tr.Gate.FindingIDs, f.ID)
		}
	}
	s.TrailerValue = &tr
	return s
}

func TestWhatToDo(t *testing.T) {
	cases := []struct {
		name    string
		outcome report.GateOutcome
		want    string
	}{
		{
			name:    "the blocking findings, attacks first, with the highest version of each package",
			outcome: report.GateFail,
			want: "1. **Payload in invisible Unicode characters (1 finding).** Do not run the code.\n" +
				"   - `src/x.js:5`\n" +
				"2. **In `go.mod`, upgrade 2 packages.** This can clear 3 findings.\n" +
				"   - `example.com/a` 1.0.0 → **1.3.0** (2 findings)\n" +
				"   - `example.com/b` 1.0.0 → **2.0.0**, the latest version (1 finding)",
		},
		{name: "nothing to do when the gate passes", outcome: report.GatePass},
		{name: "nothing to do with no gate", outcome: report.GateNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, section(write(t, gated(tc.outcome)), "What to do"))
		})
	}
}

func TestBlockingFindings(t *testing.T) {
	out := write(t, gated(report.GateFail))
	assert.Contains(t, out, "Policy rule no-high and --fail-on attacks block **4 findings** in this scan.")
	blocking := section(out, "Blocking findings (4)")
	assert.Contains(t, blocking, "| 🔴 critical | [GHSA-4](https://osv.dev/vulnerability/GHSA-4) · `f-680de930`<br>Bad \\| worse | `go/example.com/b@1.0.0`<br>`go.mod:6` | no-high |",
		"the advisory links its reference, the row names the rule, and a pipe in the title does not split the cell")
	assert.NotContains(t, blocking, "GHSA-3", "a finding that only warns does not block")
	other := section(out, "Other findings (1)")
	assert.Contains(t, other, "<details><summary><b>vulnerability</b> · 1 finding · 1 medium</summary>")
	assert.Contains(t, other, "Warned by policy rule note-medium", "a finding that warns names its rule")
}

func TestAnAttackThatDoesNotBlockStaysOpen(t *testing.T) {
	s := gated(report.GateFail)
	s.TrailerValue.Gate.FindingIDs = []string{s.FindingList[0].ID}
	out := write(t, s)
	assert.Contains(t, section(out, "Attacks to review (1)"), "`src/x.js:5`")
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
