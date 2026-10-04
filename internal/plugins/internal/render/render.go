// Package render holds the text that more than one sink shows for a
// finding. Every string from the scanned code goes through escape.
package render

import (
	"context"
	"fmt"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Subject names what the finding is about: ecosystem/name@version for a
// package, the element at fault or the path for a file, and the path for a
// manifest or an application.
func Subject(f *finding.Finding) string {
	s := f.Subject
	switch {
	case s.Package != nil:
		return escape.Line(packageSubject(s.Package))
	case s.File != nil && s.File.Element != "":
		return escape.Line(s.File.Element)
	case s.File != nil:
		return escape.Line(s.File.Path)
	case s.Manifest != nil:
		return escape.Line(s.Manifest.Path)
	case s.Application != nil:
		return escape.Line(s.Application.Root)
	}
	return ""
}

// packageSubject shows the name and the version that the manifest writes, as
// model.PackageVersion.String does.
func packageSubject(p *finding.PackageSubject) string {
	v := string(p.Ecosystem) + "/" + p.RawName
	if p.RawVersion != "" {
		v += "@" + p.RawVersion
	}
	return v
}

// SubjectID is the machine form of the subject: the PURL of a package, and
// the path otherwise.
func SubjectID(f *finding.Finding) string {
	switch s := f.Subject; {
	case s.Package != nil:
		return escape.Line(s.Package.PURL)
	case s.File != nil:
		return escape.Line(s.File.Path)
	}
	return Subject(f)
}

// Title is the title of the finding with no repeat of what Subject names:
// "GHSA-1234: Prototype pollution" for "GHSA-1234 in npm/x@1.0.0: Prototype
// pollution", and "is not pinned to a commit SHA" for "actions/checkout@v4
// is not pinned to a commit SHA".
func Title(f *finding.Finding) string {
	t := f.Title
	switch s := f.Subject; {
	case s.Package != nil:
		t = strings.Replace(t, " in "+packageSubject(s.Package), "", 1)
	case s.File != nil && s.File.Element != "":
		t = strings.TrimPrefix(t, s.File.Element+" ")
	}
	return escape.Line(t)
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

// Truncate cuts s to at most n runes, with an ellipsis at the cut.
func Truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

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
