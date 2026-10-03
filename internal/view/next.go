package view

import (
	"slices"

	"github.com/safedep/dry/semver"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/section"
	"github.com/safedep/vet/v2/report"
)

// shownFixes is the number of packages that the fix hint names.
const shownFixes = 3

// shortID is the length of the scan id prefix in a hint. vet report show
// takes a unique prefix.
const shortID = 8

// next prints the next steps of a person after the gate line: the
// upgrades that fix the top findings, the command that lists every finding
// and the command that explains one. The agent mode reads the report.
func (v *Scan) next(h *report.Header, t *report.Trailer, s Summary) {
	findings := s.Findings
	if v.mode == output.Agent || len(findings) == 0 {
		return
	}
	top := findings
	if t.Gate.Outcome == report.GateFail {
		top = slices.DeleteFunc(slices.Clone(findings), func(f *finding.Finding) bool {
			return !slices.Contains(t.Gate.FindingIDs, f.ID)
		})
		if len(top) == 0 {
			top = findings
		}
	}
	if fix := fixText(top, s.Latest); fix != "" {
		v.line(section.Hint("Fix: " + fix))
	}
	if !v.o.Saved {
		v.line(section.Hint("Full list: " + fullList(h.Scan.ID)))
	}
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	v.line(section.Hint("One finding: vet report finding show " + report.ShortID(top[0].ID, report.ShortIDLength(ids))))
}

// fixText names the upgrades that fix the findings, the most severe
// first: "upgrade minimist to 1.2.8 and lodash to 4.18.1". A package with
// many findings takes the highest version. A vulnerability with no fixed
// version takes the latest version of the package, as its remediation
// does. It is empty when no finding has a version above the one in use.
func fixText(findings []*finding.Finding, latest map[string]string) string {
	type fix struct{ name, version string }
	var keys []string
	fixes := map[string]*fix{}
	for _, f := range findings {
		p, version := upgrade(f, latest)
		if p == nil {
			continue
		}
		key := string(p.Ecosystem) + "/" + p.Name
		x, ok := fixes[key]
		if !ok {
			x = &fix{name: p.Name}
			fixes[key] = x
			keys = append(keys, key)
		}
		if x.version == "" || semver.IsAhead(x.version, version) {
			x.version = version
		}
	}
	if len(keys) == 0 {
		return ""
	}
	parts := make([]string, 0, shownFixes)
	for _, k := range keys[:min(len(keys), shownFixes)] {
		parts = append(parts, escape.Line(fixes[k].name)+" to "+escape.Line(fixes[k].version))
	}
	return "upgrade " + joinAnd(parts)
}

// upgrade returns the package of a finding and the version that fixes it,
// or nil when the finding names no version above the one in use.
func upgrade(f *finding.Finding, latest map[string]string) (*finding.PackageSubject, string) {
	p := f.Subject.Package
	if p == nil || f.Remediation == nil {
		return nil, ""
	}
	version := f.Remediation.FixedVersion
	if version == "" && f.Family == finding.FamilyVulnerability {
		version = latest[p.PURL]
	}
	if !semver.IsAhead(p.Version, version) {
		return nil, ""
	}
	return p, version
}

func fullList(scanID string) string {
	if scanID == "" {
		return "vet report show --all"
	}
	return "vet report show " + scanID[:min(len(scanID), shortID)] + " --all"
}
