package plugintest

import (
	"fmt"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// pnpmBinaries are the platform packages that the pnpm package installs.
var pnpmBinaries = []string{
	"android-arm64", "android-x64", "darwin-arm64", "darwin-x64", "freebsd-x64",
	"linux-arm64", "linux-arm64-musl", "linux-ppc64", "linux-riscv64", "linux-s390x",
	"linux-x64", "linux-x64-musl", "win32-arm64", "win32-x64",
}

// UpgradeReport returns a pull request report that upgrades pnpm and its 14
// platform packages to a version inside the cooldown window. A policy rule
// fails the 15 cooldown findings. Nine findings of other controls stay
// below the gate. It is a synthetic copy of a real pull request.
func UpgradeReport() *MemState {
	published := time.Date(2026, 10, 21, 11, 15, 0, 0, time.UTC)
	m := &model.Manifest{ID: "m-1", Path: "pnpm-lock.yaml", Ecosystem: model.EcosystemNpm, Kind: model.ManifestKindLockfile}
	pkg := func(name, version, previous string, line int) *model.Package {
		p := &model.Package{
			ID: model.MustPackageVersion(model.EcosystemNpm, name, version), Line: line,
			Change: model.ChangeUpgraded, PreviousVersion: previous,
		}
		if previous == "" {
			p.Change = model.ChangeAdded
		}
		m.Packages = append(m.Packages, p)
		return p
	}

	gate := &finding.GateRecord{
		Action: finding.GateActionFail, Rules: []string{"package-cooldown"},
		Help: "Wait until the version is older than the cooldown, or pin an older version.",
	}
	var findings []*finding.Finding
	var blocked []string
	cooldown := func(p *model.Package, at time.Time) {
		f := finding.ForPackage(finding.Meta{
			ControlID: "dependency-cooldown", Family: finding.FamilyCooldown, Severity: finding.SeverityHigh,
			Title: p.ID.String() + " was published 1 day ago",
			Description: "The registry published this version on 2026-10-21. The version is eligible on 2026-10-23. " +
				"The cooldown window is 2 days, from flag --cooldown-days. " +
				"The setting plugins.dependency-cooldown.options.days sets the window, also in a flag or a variable",
		}, m.Path, p, finding.Key{})
		f.Change = p.Change
		f.Evidence = []finding.Evidence{{Source: "insights", Summary: "published at " + at.Format(time.RFC3339)}}
		f.Remediation = &finding.Remediation{Summary: "Wait until 2026-10-23, or keep version " + p.PreviousVersion + "."}
		f.Gate = gate
		findings = append(findings, &f)
		blocked = append(blocked, f.ID)
	}
	cooldown(pkg("pnpm", "12.15.0", "12.8.2", 92), published)
	for i, b := range pnpmBinaries {
		cooldown(pkg("@pnpm/exe."+b, "12.15.0", "12.8.2", 20+i*5), published.Add(time.Duration(i)*7*time.Second))
	}

	other := func(f finding.Finding) {
		f.Change = model.ChangeAdded
		findings = append(findings, &f)
	}
	onPackage := func(control string, family finding.Family, sev finding.Severity, title string, p *model.Package) {
		other(finding.ForPackage(finding.Meta{ControlID: control, Family: family, Severity: sev, Title: title}, m.Path, p, finding.Key{}))
	}
	for _, n := range []struct {
		name, version string
		line, days    int
	}{{"lefthook-android-arm64", "2.2.2", 4131, 9}, {"@codemirror/streamparser", "6.0.0", 684, 15}} {
		onPackage("new-unpopular-package", finding.FamilyReputation, finding.SeverityMedium,
			fmt.Sprintf("%s is new: its first version is %d days old", n.name, n.days), pkg(n.name, n.version, "", n.line))
	}
	for _, n := range []struct {
		name, version, previous string
		line                    int
	}{
		{"lefthook", "2.2.2", "2.1.14", 4186},
		{"@typescript-eslint/scope-manager", "8.71.2", "8.70.1", 3034},
		{"@oxc-parser/binding-linux-x64-musl", "0.154.0", "0.150.0", 1392},
		{"@nosecone/next", "1.14.1", "1.13.0", 1220},
	} {
		p := pkg(n.name, n.version, n.previous, n.line)
		onPackage("provenance-lost", finding.FamilyHygiene, finding.SeverityMedium,
			fmt.Sprintf("%s has no provenance, and %s had one", p.ID, n.previous), p)
	}
	unbash := pkg("unbash", "6.0.0", "4.0.11", 5289)
	onPackage("version-anomaly", finding.FamilyReputation, finding.SeverityMedium,
		unbash.ID.String()+": the upgrade jumps from 4.0.11 to 6.0.0", unbash)
	onPackage("scorecard-low", finding.FamilyHygiene, finding.SeverityInfo,
		"source-map-js has an OpenSSF Scorecard score of 2.8", pkg("source-map-js", "1.2.2", "", 5129))
	other(finding.ForFile(finding.Meta{
		ControlID: "agent-instruction-change", Family: finding.FamilyAgentConfig, Severity: finding.SeverityInfo,
		Title: "Agent instruction file CLAUDE.md",
	}, finding.Locus{Path: "CLAUDE.md", StartLine: 1, EndLine: 1}, finding.Key{Discriminator: "instructions"}))

	s := &MemState{ManifestList: []*model.Manifest{m}, FindingList: findings}
	h := s.Header()
	h.Tool.Version = "2.0.0-alpha.20261014124335"
	h.Scan.Mode, h.Scan.BaseRef = report.ScanModeDelta, "origin/main"
	s.Trailer().Gate = report.Gate{
		Outcome: report.GateFail, Policy: "1c8a58d6e27559015e1621a830dc20e9dc6b4bd0:.github/vet/policy.yml",
		Rules: []string{"package-cooldown"}, FindingIDs: blocked,
	}
	return s
}
