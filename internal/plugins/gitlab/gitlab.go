// Package gitlab is the GitLab dependency scanning report format, schema
// 15.2.1. A GitLab CI job uploads the file as artifacts:reports:
// dependency_scanning, and GitLab shows the findings in the merge request
// and the vulnerability report.
package gitlab

import (
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the format name.
const Name = "gitlab"

const (
	schemaURL     = "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/15.2.1/dist/dependency-scanning-report-format.json"
	schemaVersion = "15.2.1"
	timeLayout    = "2006-01-02T15:04:05"
	// maxIdentifiers is the number of identifiers that GitLab keeps for
	// one vulnerability.
	maxIdentifiers = 20
	docsURL        = "https://docs.safedep.io"
)

type reportFile struct {
	Schema          string          `json:"schema"`
	Version         string          `json:"version"`
	Scan            scan            `json:"scan"`
	Vulnerabilities []vulnerability `json:"vulnerabilities"`
}

type scan struct {
	Analyzer  scanner `json:"analyzer"`
	Scanner   scanner `json:"scanner"`
	Type      string  `json:"type"`
	StartTime string  `json:"start_time"`
	EndTime   string  `json:"end_time"`
	Status    string  `json:"status"`
}

type scanner struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Vendor  vendor `json:"vendor"`
}

type vendor struct {
	Name string `json:"name"`
}

type vulnerability struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Severity    string       `json:"severity"`
	Solution    string       `json:"solution,omitempty"`
	Identifiers []identifier `json:"identifiers"`
	Links       []link       `json:"links,omitempty"`
	Location    location     `json:"location"`
}

type identifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url,omitempty"`
}

type link struct {
	URL string `json:"url"`
}

type location struct {
	File       string     `json:"file"`
	Dependency dependency `json:"dependency"`
}

type dependency struct {
	Package pkg    `json:"package"`
	Version string `json:"version"`
	Direct  bool   `json:"direct"`
}

type pkg struct {
	Name string `json:"name"`
}

// Sink writes the gitlab format.
type Sink struct{}

// New builds the sink. It has no options.
func New(cfg plugin.Config) (plugin.Sink, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, err
	}
	return Sink{}, nil
}

// Write writes the report. The schema needs a dependency for each
// vulnerability, so the file holds the package findings only. A workflow
// or a file finding goes to the other formats, such as sarif. GitLab has
// no suppression, so a suppressed finding is not in the file.
func (Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	h := r.Header()
	tool := scanner{ID: "vet", Name: h.Tool.Name, Version: h.Tool.Version, Vendor: vendor{Name: "SafeDep"}}
	end := time.Now()
	if t := r.Trailer(); t != nil && !t.FinishedAt.IsZero() {
		end = t.FinishedAt
	}
	out := reportFile{
		Schema: schemaURL, Version: schemaVersion,
		Scan: scan{
			Analyzer: tool, Scanner: tool, Type: "dependency_scanning", Status: "success",
			StartTime: h.Scan.StartedAt.UTC().Format(timeLayout), EndTime: end.UTC().Format(timeLayout),
		},
		Vulnerabilities: []vulnerability{},
	}
	for rec, err := range r.Records(ctx) {
		if err != nil {
			return err
		}
		f := rec.Finding
		if rec.Kind != report.KindFinding || f == nil || f.Suppressed() || f.Subject.Package == nil {
			continue
		}
		out.Vulnerabilities = append(out.Vulnerabilities, toVulnerability(f))
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func toVulnerability(f *finding.Finding) vulnerability {
	p := f.Subject.Package
	v := vulnerability{
		ID: f.ID, Name: f.Title, Description: description(f), Severity: severity(f.Severity),
		Identifiers: identifiers(f),
		Location: location{
			File:       p.ManifestPath,
			Dependency: dependency{Package: pkg{Name: p.Name}, Version: p.Version, Direct: p.Direct},
		},
	}
	if f.Remediation != nil {
		v.Solution = f.Remediation.Summary
	}
	for _, ref := range f.References {
		v.Links = append(v.Links, link{URL: ref})
	}
	return v
}

func description(f *finding.Finding) string {
	parts := []string{}
	if f.Description != "" {
		parts = append(parts, f.Description)
	}
	for _, e := range f.Evidence {
		parts = append(parts, e.Source+": "+e.Summary)
	}
	return strings.Join(parts, "\n\n")
}

var advisoryIDs = []struct {
	kind string
	re   *regexp.Regexp
	url  string
}{
	{"cve", regexp.MustCompile(`\bCVE-\d{4}-\d{4,}\b`), "https://nvd.nist.gov/vuln/detail/"},
	{"ghsa", regexp.MustCompile(`\bGHSA(?:-[23456789cfghjmpqrvwx]{4}){3}\b`), "https://github.com/advisories/"},
	{"cwe", regexp.MustCompile(`\bCWE-\d+\b`), "https://cwe.mitre.org/data/definitions/"},
}

// identifiers puts the control id first. GitLab groups the findings by
// the first identifier. The CVE, GHSA and CWE ids that the title and the
// evidence name come next.
func identifiers(f *finding.Finding) []identifier {
	out := []identifier{{Type: "safedep_vet", Name: f.ControlID, Value: f.ControlID, URL: docsURL}}
	text := f.Title
	for _, e := range f.Evidence {
		text += "\n" + e.Summary
	}
	seen := map[string]bool{}
	for _, a := range advisoryIDs {
		for _, id := range a.re.FindAllString(text, -1) {
			if seen[id] {
				continue
			}
			seen[id] = true
			url := a.url + id
			if a.kind == "cwe" {
				url = a.url + strings.TrimPrefix(id, "CWE-") + ".html"
			}
			out = append(out, identifier{Type: a.kind, Name: id, Value: id, URL: url})
		}
	}
	return out[:min(len(out), maxIdentifiers)]
}

func severity(s finding.Severity) string {
	if !s.Valid() {
		return "Unknown"
	}
	return s.Title()
}
