// Package render holds the text that more than one sink shows for a
// finding. Every string from the scanned code goes through escape.
package render

import (
	"context"
	"fmt"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Subject names what the finding is about: ecosystem/name@version for a
// package, and the path for a file, a manifest or an application.
func Subject(f *finding.Finding) string {
	s := f.Subject
	switch {
	case s.Package != nil:
		v := string(s.Package.Ecosystem) + "/" + s.Package.Name
		if s.Package.Version != "" {
			v += "@" + s.Package.Version
		}
		return escape.Line(v)
	case s.File != nil:
		return escape.Line(s.File.Path)
	case s.Manifest != nil:
		return escape.Line(s.Manifest.Path)
	case s.Application != nil:
		return escape.Line(s.Application.Root)
	}
	return ""
}

// SubjectID is the machine form of the subject: the PURL of a package, and
// the path otherwise.
func SubjectID(f *finding.Finding) string {
	if p := f.Subject.Package; p != nil {
		return escape.Line(p.PURL)
	}
	return Subject(f)
}

// Where is path:line of the finding, or the manifest path.
func Where(f *finding.Finding) string {
	if l := f.Locus; l != nil && l.Path != "" {
		if l.StartLine > 0 {
			return escape.Line(fmt.Sprintf("%s:%d", l.Path, l.StartLine))
		}
		return escape.Line(l.Path)
	}
	if p := f.Subject.Package; p != nil {
		return escape.Line(p.ManifestPath)
	}
	return Subject(f)
}

// Text escapes free text from a finding, such as a title.
func Text(s string) string { return escape.Line(s) }

// EachRecord calls fn for each record of the report, in report order.
func EachRecord(ctx context.Context, r plugin.Report, fn func(*report.Record) error) error {
	for rec, err := range r.Records(ctx) {
		if err != nil {
			return err
		}
		if err := fn(rec); err != nil {
			return err
		}
	}
	return nil
}

// EachFinding calls fn for each finding of the report, the most severe
// first.
func EachFinding(ctx context.Context, r plugin.Report, fn func(*finding.Finding) error) error {
	return EachRecord(ctx, r, func(rec *report.Record) error {
		if rec.Finding == nil {
			return nil
		}
		return fn(rec.Finding)
	})
}
