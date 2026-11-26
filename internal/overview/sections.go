package overview

import (
	"slices"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/report"
)

// Sections split the open findings by what a person does with them. Each
// part keeps the finding.Compare order.
type Sections struct {
	// Blocking are the findings that fail the gate.
	Blocking []*finding.Finding
	// Attacks are the attack findings that do not fail the gate.
	Attacks []*finding.Finding
	// Review are the critical and high findings that do not fail the gate
	// and are not attacks.
	Review []*finding.Finding
	// Rest are the other findings.
	Rest []*finding.Finding
}

// Sections splits the findings by the gate.
func (s Overview) Sections(g report.Gate) Sections {
	blocks := map[string]bool{}
	if g.Outcome == report.GateFail {
		for _, id := range g.FindingIDs {
			blocks[id] = true
		}
	}
	var sec Sections
	for _, f := range s.Findings {
		switch {
		case blocks[f.ID]:
			sec.Blocking = append(sec.Blocking, f)
		case f.Attack != nil:
			sec.Attacks = append(sec.Attacks, f)
		case f.Severity.AtLeast(finding.SeverityHigh):
			sec.Review = append(sec.Review, f)
		default:
			sec.Rest = append(sec.Rest, f)
		}
	}
	return sec
}

// ToReview are the attacks and the review findings, in finding.Compare
// order.
func (s Sections) ToReview() []*finding.Finding {
	fs := slices.Concat(s.Attacks, s.Review)
	slices.SortStableFunc(fs, finding.Compare)
	return fs
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
