// Package overview reads what a person sees first in a report: the
// findings that no suppression hides, the most severe first, the
// diagnostics, and what a pull request changes. The terminal view and the
// sinks share it.
package overview

import (
	"context"
	"slices"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Overview is what a person sees first in a report.
type Overview struct {
	Diagnostics []*report.Diagnostic
	// Findings are the findings that no suppression hides, the most
	// severe first.
	Findings []*finding.Finding
	// Latest maps the key of a package to its latest version, when the
	// insights know it.
	Latest  map[model.PackageKey]string
	Changes Changes
}

// Changes counts what a pull request changes.
type Changes struct {
	Packages, Workflows, Unchanged int
}

// Read reads the overview of a report in one pass.
func Read(ctx context.Context, r plugin.Report) (Overview, error) {
	s := Overview{Latest: map[model.PackageKey]string{}}
	for rec, err := range r.Records(ctx) {
		if err != nil {
			return Overview{}, err
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

func (s *Overview) addPackage(p *report.PackageEntry) {
	if p.Insight != nil && p.Insight.LatestVersion != "" {
		s.Latest[p.ID.Key()] = p.Insight.LatestVersion
	}
	if p.Change.Introduces() {
		s.Changes.Packages++
		return
	}
	s.Changes.Unchanged++
}
