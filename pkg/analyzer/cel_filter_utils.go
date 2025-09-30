package analyzer

import (
	"fmt"
	"io"

	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/safedep/vet/pkg/models"
)

type celFilterStat struct {
	evaluatedManifests int
	evaluatedPackages  int
	matchedPackages    int
	errCount           int
}

func (s *celFilterStat) IncScannedManifest() {
	s.evaluatedManifests += 1
}

func (s *celFilterStat) IncEvaluatedPackage() {
	s.evaluatedPackages += 1
}

func (s *celFilterStat) IncMatchedPackage() {
	s.matchedPackages += 1
}

func (s *celFilterStat) IncError(_ error) {
	s.errCount += 1
}

func (s *celFilterStat) EvaluatedManifests() int {
	return s.evaluatedManifests
}

func (s *celFilterStat) EvaluatedPackages() int {
	return s.evaluatedPackages
}

func (s *celFilterStat) MatchedPackages() int {
	return s.matchedPackages
}

func (s *celFilterStat) ErrorCount() int {
	return s.errCount
}

func (s *celFilterStat) PrintStatMessage(writer io.Writer) {
	fmt.Fprintf(writer, "%s\n", text.Bold.Sprint("Filter evaluated with ",
		s.matchedPackages, " out of ", s.evaluatedPackages, " uniquely matched and ",
		s.errCount, " error(s) ", "across ", s.evaluatedManifests,
		" manifest(s)"))
}

// celFilterV2MatchedPackage holds information about a matched package
type celFilterV2MatchedPackage struct {
	pkg    *models.Package
	policy *policyv1.Policy
	rule   *policyv1.Rule
}

func newCelFilterV2MatchedPackage(p *models.Package,
	policy *policyv1.Policy, rule *policyv1.Rule,
) *celFilterV2MatchedPackage {
	return &celFilterV2MatchedPackage{
		pkg:    p,
		policy: policy,
		rule:   rule,
	}
}

// celFilterMatchData holds information about a package matching the filter
// This is a generic struct and can hold non-package matches as well for extensibility
type celFilterV2MatchData struct {
	packages []*celFilterV2MatchedPackage
	stats    celFilterStat
}

func newCelFilterMatchData(pkgs []*celFilterV2MatchedPackage,
	stats celFilterStat,
) *celFilterV2MatchData {
	return &celFilterV2MatchData{
		packages: pkgs,
		stats:    stats,
	}
}

func (c *celFilterV2MatchData) renderTable(writer io.Writer) error {
	if c.stats.EvaluatedPackages() == 0 {
		return nil
	}

	// Build table
	t := table.NewWriter()
	t.SetOutputMirror(writer)
	t.SetStyle(table.StyleLight)

	t.AppendHeader(table.Row{"Package", "Version", "Ecosystem", "Policy"})
	for _, mp := range c.packages {
		pkg := mp.pkg
		t.AppendRow(table.Row{
			pkg.GetName(), pkg.GetVersion(), string(pkg.Ecosystem),
			fmt.Sprintf("%s/%s", mp.policy.GetName(), mp.rule.GetName()),
		})
	}

	t.AppendFooter(table.Row{"Total", c.stats.EvaluatedPackages(), ""})
	t.AppendFooter(table.Row{"Matched", c.stats.MatchedPackages(), ""})
	t.AppendFooter(table.Row{"Unmatched", c.stats.EvaluatedPackages() - c.stats.MatchedPackages(), ""})

	if c.stats.MatchedPackages() > 0 {
		fmt.Fprintf(writer, "\nPackages matched by filter suite (using Policy Input schema):\n")
		t.Render()
	}

	return nil
}
