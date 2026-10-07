package policy

import (
	"slices"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/report"
)

// Gate collects the outcomes of a scan into the gate of the report.
type Gate struct {
	e     *Evaluator
	fail  bool
	rules []string
	ids   []string
}

// NewGate returns an empty gate of the evaluator.
func (e *Evaluator) NewGate() *Gate { return &Gate{e: e} }

// Add counts the outcome of one finding.
func (g *Gate) Add(f *finding.Finding, o Outcome) {
	if !o.Fail {
		return
	}
	g.fail = true
	if !slices.Contains(g.ids, f.ID) {
		g.ids = append(g.ids, f.ID)
	}
	for _, r := range append(slices.Clone(o.FailRules), o.BrokenRules...) {
		if !slices.Contains(g.rules, r) {
			g.rules = append(g.rules, r)
		}
	}
}

// Result returns the gate. With no severity and no policy, the scan has no
// gate (decisions D3).
func (g *Gate) Result() report.Gate {
	if !g.e.Gated() {
		return report.Gate{Outcome: report.GateNone}
	}
	out := report.Gate{Outcome: report.GatePass, FailOn: g.e.failOn, Policy: strings.Join(g.e.p.Sources, ", ")}
	if g.fail {
		out.Outcome = report.GateFail
		out.Rules = slices.Sorted(slices.Values(g.rules))
		out.FindingIDs = slices.Clone(g.ids)
	}
	return out
}
