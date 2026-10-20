// Package overview reads what a person sees first in a report. That is the
// findings that no suppression hides, with the attacks and then the most
// severe first, the diagnostics, and what a pull request changes. The
// terminal view and the sinks share it.
package overview

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Overview is what a person sees first in a report.
type Overview struct {
	Diagnostics []*report.Diagnostic
	// Findings are the findings that no suppression hides, in
	// finding.Compare order.
	Findings []*finding.Finding
	// Suppressed are the findings that a suppression hides.
	Suppressed []*finding.Finding
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
		case rec.Finding != nil:
			s.Suppressed = append(s.Suppressed, rec.Finding)
		case rec.Package != nil:
			s.addPackage(rec.Package)
		case rec.Manifest != nil && rec.Manifest.Kind == model.ManifestKindWorkflow && rec.Manifest.Change.Introduces():
			s.Changes.Workflows++
		}
	}
	slices.SortStableFunc(s.Findings, finding.Compare)
	return s, nil
}

// ReachSummary counts the reach of the vulnerability findings, riskiest
// first, with the causes of each level, as "1 called, 2 imported (1 no
// symbol data, 1 transitive), 1 not called". It is empty with no reach.
func (s Overview) ReachSummary() string {
	type level struct {
		n      int
		causes map[finding.ReachCause]int
	}
	levels := map[finding.ReachLevel]*level{}
	for _, f := range s.Findings {
		if f.Reach == nil {
			continue
		}
		l := levels[f.Reach.Level]
		if l == nil {
			l = &level{causes: map[finding.ReachCause]int{}}
			levels[f.Reach.Level] = l
		}
		l.n++
		if f.Reach.Cause != "" {
			l.causes[f.Reach.Cause]++
		}
	}
	order := slices.SortedFunc(maps.Keys(levels), func(a, b finding.ReachLevel) int { return b.Rank() - a.Rank() })
	parts := make([]string, 0, len(order))
	for _, lv := range order {
		l := levels[lv]
		part := fmt.Sprintf("%d %s", l.n, lv.Text())
		var causes []string
		for _, c := range slices.Sorted(maps.Keys(l.causes)) {
			causes = append(causes, fmt.Sprintf("%d %s", l.causes[c], c.Text()))
		}
		if len(causes) > 0 {
			part += " (" + strings.Join(causes, ", ") + ")"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
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
