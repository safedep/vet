package view

import (
	"slices"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/overview"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/section"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// shownFixes is the number of packages that the fix hint names.
const shownFixes = 3

// next prints the next steps of a person after the gate line: the
// upgrades that fix the top findings, the command that lists every finding
// and the command that explains one. The agent mode reads the report.
func (v *Scan) next(h *report.Header, t *report.Trailer, s overview.Overview) {
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
		v.line(section.Hint("Full list: " + overview.FullList(h.Scan.ID)))
	}
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.ID
	}
	v.line(section.Hint("One finding: vet report finding show " + report.ShortID(top[0].ID, report.ShortIDLength(ids))))
}

// fixText names the upgrades that fix the findings, the most severe
// first: "upgrade minimist to 1.2.8 and lodash to 4.18.1". It is empty when
// no finding has a version above the one in use.
func fixText(findings []*finding.Finding, latest map[model.PackageKey]string) string {
	ups := overview.Upgrades(findings, latest)
	if len(ups) == 0 {
		return ""
	}
	parts := make([]string, 0, shownFixes)
	for _, u := range ups[:min(len(ups), shownFixes)] {
		parts = append(parts, escape.Line(u.Name)+" to "+escape.Line(u.To.RawVersion()))
	}
	return "upgrade " + joinAnd(parts)
}
