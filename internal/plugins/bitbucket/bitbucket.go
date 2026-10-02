// Package bitbucket is the Bitbucket Code Insights format. The file holds
// the report and its annotations. A Bitbucket Pipelines step sends the
// report with PUT .../commit/{commit}/reports/{id} and the annotations
// with POST .../reports/{id}/annotations.
package bitbucket

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"slices"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/render"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the format name.
const Name = "bitbucket"

// The limits of the Code Insights API.
const (
	maxAnnotations = 1000
	maxSummary     = 450
	maxDetails     = 2000
	maxTitle       = 450
)

type file struct {
	Report      codeInsightsReport `json:"report"`
	Annotations []annotation       `json:"annotations"`
}

type codeInsightsReport struct {
	Title      string  `json:"title"`
	Details    string  `json:"details"`
	ReportType string  `json:"report_type"`
	Reporter   string  `json:"reporter"`
	Result     string  `json:"result,omitempty"`
	Data       []datum `json:"data"`
}

type datum struct {
	Title string `json:"title"`
	Type  string `json:"type"`
	Value any    `json:"value"`
}

type annotation struct {
	ExternalID     string `json:"external_id"`
	Title          string `json:"title"`
	AnnotationType string `json:"annotation_type"`
	Summary        string `json:"summary"`
	Details        string `json:"details,omitempty"`
	Severity       string `json:"severity"`
	Path           string `json:"path,omitempty"`
	Line           int    `json:"line,omitempty"`
	Link           string `json:"link,omitempty"`
}

// Sink writes the bitbucket format.
type Sink struct{}

// New builds the sink. It has no options.
func New(cfg plugin.Config) (plugin.Sink, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, err
	}
	return Sink{}, nil
}

// Write writes the report and one annotation for each finding that no
// policy suppressed. The API keeps 1000 annotations, so the file keeps
// the 1000 most severe.
func (Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	var findings []*finding.Finding
	for rec, err := range r.Records(ctx) {
		if err != nil {
			return err
		}
		if rec.Kind == report.KindFinding && rec.Finding != nil && !rec.Finding.Suppressed() {
			findings = append(findings, rec.Finding)
		}
	}
	slices.SortFunc(findings, finding.Compare)

	out := file{Report: summary(r, findings), Annotations: []annotation{}}
	for _, f := range findings[:min(len(findings), maxAnnotations)] {
		out.Annotations = append(out.Annotations, toAnnotation(f))
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// summary builds the report. The gate sets the result. With no gate the
// report has no result, as a plain scan does not fail.
func summary(r plugin.Report, findings []*finding.Finding) codeInsightsReport {
	h := r.Header()
	bySeverity := map[finding.Severity]int{}
	for _, f := range findings {
		bySeverity[f.Severity]++
	}
	out := codeInsightsReport{
		Title:      "SafeDep vet",
		Details:    fmt.Sprintf("vet found %d supply chain findings.", len(findings)),
		ReportType: "SECURITY",
		Reporter:   "SafeDep vet " + h.Tool.Version,
		Data:       []datum{{Title: "Findings", Type: "NUMBER", Value: len(findings)}},
	}
	for _, s := range []finding.Severity{finding.SeverityCritical, finding.SeverityHigh, finding.SeverityMedium, finding.SeverityLow} {
		out.Data = append(out.Data, datum{Title: s.Title(), Type: "NUMBER", Value: bySeverity[s]})
	}
	if t := r.Trailer(); t != nil {
		out.Data = append(out.Data,
			datum{Title: "Suppressed", Type: "NUMBER", Value: t.Summary.Suppressed},
			datum{Title: "Packages", Type: "NUMBER", Value: t.Summary.Packages},
		)
		switch t.Gate.Outcome {
		case report.GatePass:
			out.Result = "PASSED"
		case report.GateFail:
			out.Result = "FAILED"
		}
	}
	if h.Scan.BaseRef != "" {
		out.Data = append(out.Data, datum{Title: "Base ref", Type: "TEXT", Value: h.Scan.BaseRef})
	}
	return out
}

func toAnnotation(f *finding.Finding) annotation {
	a := annotation{
		ExternalID: f.ID, Title: render.Truncate(f.Title, maxTitle), AnnotationType: annotationType(f.Family),
		Summary: render.Truncate(f.Title, maxSummary), Details: render.Truncate(details(f), maxDetails),
		Severity: annotationSeverity(f.Severity),
	}
	switch {
	case f.Locus != nil && f.Locus.Path != "":
		a.Path, a.Line = f.Locus.Path, f.Locus.StartLine
	case f.Subject.Package != nil:
		a.Path = f.Subject.Package.ManifestPath
	case f.Subject.Manifest != nil:
		a.Path = f.Subject.Manifest.Path
	case f.Subject.File != nil:
		a.Path = f.Subject.File.Path
	}
	if len(f.References) > 0 {
		a.Link = f.References[0]
	}
	return a
}

func details(f *finding.Finding) string {
	s := f.Description
	if f.Remediation != nil && f.Remediation.Summary != "" {
		if s != "" {
			s += " "
		}
		s += f.Remediation.Summary
	}
	return s
}

func annotationType(f finding.Family) string {
	switch f {
	case finding.FamilyVulnerability, finding.FamilyMalware:
		return "VULNERABILITY"
	}
	return "CODE_SMELL"
}

// annotationSeverity maps info to LOW. Code Insights has no info level.
func annotationSeverity(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "CRITICAL"
	case finding.SeverityHigh:
		return "HIGH"
	case finding.SeverityMedium:
		return "MEDIUM"
	}
	return "LOW"
}
