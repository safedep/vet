package view

import (
	"context"
	"slices"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Summary is what the end of the view reads from a report.
type Summary struct {
	Diagnostics []*report.Diagnostic
	// Findings are the findings that no suppression hides, the most
	// severe first.
	Findings []*finding.Finding
	// Latest maps the PURL of a package to its latest version, when the
	// insights know it.
	Latest  map[string]string
	Changes Changes
}

// Changes counts what a pull request changes.
type Changes struct {
	Packages, Workflows, Unchanged int
}

// Summarize reads the summary of a report in one pass.
func Summarize(ctx context.Context, r plugin.Report) (Summary, error) {
	s := Summary{Latest: map[string]string{}}
	for rec, err := range r.Records(ctx) {
		if err != nil {
			return Summary{}, err
		}
		switch {
		case rec.Diagnostic != nil:
			s.Diagnostics = append(s.Diagnostics, rec.Diagnostic)
		case rec.Finding != nil && rec.Finding.Suppression == nil:
			s.Findings = append(s.Findings, rec.Finding)
		case rec.Package != nil:
			s.addPackage(rec.Package)
		case rec.Manifest != nil && rec.Manifest.Kind == model.ManifestKindWorkflow && rec.Manifest.Change.Introduces():
			s.Changes.Workflows++
		}
	}
	slices.SortStableFunc(s.Findings, finding.Compare)
	return s, nil
}

func (s *Summary) addPackage(p *report.PackageEntry) {
	if p.Insight != nil && p.Insight.LatestVersion != "" {
		s.Latest[p.PURL] = p.Insight.LatestVersion
	}
	if p.Change.Introduces() {
		s.Changes.Packages++
		return
	}
	s.Changes.Unchanged++
}
