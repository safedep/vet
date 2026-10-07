// Package sarif is the SARIF 2.1.0 format, for code scanning. Each control
// id is a rule, and each finding is a result. A suppressed finding is a
// result with an external suppression.
package sarif

import (
	"cmp"
	"context"
	"encoding/json"
	"io"
	"slices"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the format name.
const Name = "sarif"

const (
	schemaURI   = "https://json.schemastore.org/sarif-2.1.0.json"
	toolURI     = "https://github.com/safedep/vet"
	fingerprint = "vetFindingId/v1"
)

type log struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []rule `json:"rules"`
}

type rule struct {
	ID               string     `json:"id"`
	ShortDescription text       `json:"shortDescription"`
	Properties       properties `json:"properties"`
}

type text struct {
	Text string `json:"text"`
}

type properties struct {
	SecuritySeverity string   `json:"security-severity,omitempty"`
	Tags             []string `json:"tags,omitempty"`
}

type result struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             text              `json:"message"`
	Locations           []location        `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Suppressions        []suppression     `json:"suppressions,omitempty"`
	Properties          properties        `json:"properties"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           *region          `json:"region,omitempty"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine,omitempty"`
}

type suppression struct {
	Kind          string `json:"kind"`
	Justification string `json:"justification"`
}

// Sink writes the sarif format.
type Sink struct{}

// New builds the sink. It has no options.
func New(cfg plugin.Config) (plugin.Sink, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, err
	}
	return Sink{}, nil
}

// Write writes the SARIF log. It holds the findings of the report, which a
// SARIF log needs in one document.
func (Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	rn := run{
		Tool:    tool{Driver: driver{Name: r.Header().Tool.Name, Version: r.Header().Tool.Version, InformationURI: toolURI, Rules: []rule{}}},
		Results: []result{},
	}
	rules := map[string]bool{}
	for rec, err := range r.Records(ctx) {
		if err != nil {
			return err
		}
		f := rec.Finding
		if rec.Kind != report.KindFinding || f == nil {
			continue
		}
		if id := ruleID(f); !rules[id] {
			rules[id] = true
			rn.Tool.Driver.Rules = append(rn.Tool.Driver.Rules, rule{
				ID: id, ShortDescription: text{Text: id},
				Properties: properties{Tags: []string{"security", string(f.Family)}},
			})
		}
		rn.Results = append(rn.Results, toResult(f))
	}
	slices.SortFunc(rn.Tool.Driver.Rules, func(a, b rule) int { return cmp.Compare(a.ID, b.ID) })
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	return enc.Encode(log{Schema: schemaURI, Version: "2.1.0", Runs: []run{rn}})
}

// ruleID is the control id. A finding of a package rule adds the id of the
// rule, as policy/no-evil, so that code scanning keeps two rules apart.
func ruleID(f *finding.Finding) string {
	if g := f.Gate; f.Family == finding.FamilyPolicy && g != nil {
		if ids := append(slices.Clone(g.Rules), g.Broken...); len(ids) > 0 {
			return f.ControlID + "/" + ids[0]
		}
	}
	return f.ControlID
}

func toResult(f *finding.Finding) result {
	msg := f.Title
	if f.Description != "" {
		msg += ". " + f.Description
	}
	res := result{
		RuleID: ruleID(f), Level: level(f.Severity), Message: text{Text: msg},
		PartialFingerprints: map[string]string{fingerprint: f.ID},
		Properties:          properties{SecuritySeverity: securitySeverity(f.Severity), Tags: []string{string(f.Severity), string(f.Family)}},
	}
	if loc := locationOf(f); loc != nil {
		res.Locations = []location{*loc}
	}
	if s := f.Suppression; s != nil {
		res.Suppressions = []suppression{{Kind: "external", Justification: s.Reason}}
	}
	return res
}

func locationOf(f *finding.Finding) *location {
	path, line := "", 0
	switch {
	case f.Locus != nil && f.Locus.Path != "":
		path, line = f.Locus.Path, f.Locus.StartLine
	case f.Subject.Package != nil:
		path = f.Subject.Package.ManifestPath
	case f.Subject.Manifest != nil:
		path = f.Subject.Manifest.Path
	}
	if path == "" {
		return nil
	}
	loc := &location{PhysicalLocation: physicalLocation{ArtifactLocation: artifactLocation{URI: path}}}
	if line > 0 {
		end := line
		if f.Locus.EndLine > line {
			end = f.Locus.EndLine
		}
		loc.PhysicalLocation.Region = &region{StartLine: line, EndLine: end}
	}
	return loc
}

func level(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical, finding.SeverityHigh:
		return "error"
	case finding.SeverityMedium:
		return "warning"
	}
	return "note"
}

// securitySeverity is the score that GitHub code scanning maps back to a
// severity.
func securitySeverity(s finding.Severity) string {
	switch s {
	case finding.SeverityCritical:
		return "9.5"
	case finding.SeverityHigh:
		return "8.0"
	case finding.SeverityMedium:
		return "5.5"
	case finding.SeverityLow:
		return "2.0"
	}
	return "0.0"
}
