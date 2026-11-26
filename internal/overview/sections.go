package overview

import (
	"slices"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/report"
)

// Sections split the findings for a report that shows some findings in
// full and lists the rest.
type Sections struct {
	// Shown are the findings that fail the gate. With no failed gate, they
	// are the attacks and the critical and high findings to review.
	Shown []*finding.Finding
	// Blocking reports that Shown are the findings that fail the gate.
	Blocking bool
	// Attacks are the attacks that do not fail a gate that fails on other
	// findings, as with a gate of policy rules only. An attack never goes
	// to Rest.
	Attacks []*finding.Finding
	Rest    []*finding.Finding
}

// Sections splits the findings by the gate. Each part keeps the
// finding.Compare order.
func (s Overview) Sections(g report.Gate) Sections {
	var blocking, attacks, review, rest []*finding.Finding
	for _, f := range s.Findings {
		switch {
		case g.Outcome == report.GateFail && slices.Contains(g.FindingIDs, f.ID):
			blocking = append(blocking, f)
		case f.Attack != nil:
			attacks = append(attacks, f)
		case f.Severity.AtLeast(finding.SeverityHigh):
			review = append(review, f)
		default:
			rest = append(rest, f)
		}
	}
	if len(blocking) > 0 {
		rest = append(review, rest...)
		slices.SortStableFunc(rest, finding.Compare)
		return Sections{Shown: blocking, Blocking: true, Attacks: attacks, Rest: rest}
	}
	review = append(attacks, review...)
	slices.SortStableFunc(review, finding.Compare)
	return Sections{Shown: review, Rest: rest}
}

// shortScanID is the length of the scan id prefix in a command. vet report
// show takes a unique prefix.
const shortScanID = 8

// FullList is the command that lists each finding of a scan.
func FullList(scanID string) string {
	if scanID == "" {
		return "vet report show --all"
	}
	return "vet report show " + scanID[:min(len(scanID), shortScanID)] + " --all"
}
