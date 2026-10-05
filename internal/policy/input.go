package policy

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

// Input is what a rule reads. vet owns these types (decisions D4). An
// optional field that has no value is absent: test it with has().
type Input struct {
	Finding  FindingInput  `json:"finding"`
	Package  *PackageInput `json:"package,omitempty"`
	Manifest ManifestInput `json:"manifest"`
}

// FindingInput is the finding that the rule evaluates.
type FindingInput struct {
	ID          string `json:"id"`
	ControlID   string `json:"control_id"`
	Family      string `json:"family"`
	Severity    string `json:"severity"`
	Confidence  string `json:"confidence"`
	Title       string `json:"title"`
	Change      string `json:"change"`
	SubjectKind string `json:"subject_kind"`
	// Path is the file of the finding.
	Path string `json:"path"`
}

// PackageInput is the package of a package finding. It is an empty map
// for a file, manifest or application finding. Name and Version hold the
// canonical form, so a rule matches every spelling of one package version.
// RawName and RawVersion hold the form that the manifest writes.
type PackageInput struct {
	PURL            string `json:"purl"`
	Ecosystem       string `json:"ecosystem"`
	Name            string `json:"name"`
	Version         string `json:"version"`
	RawName         string `json:"raw_name"`
	RawVersion      string `json:"raw_version"`
	Direct          bool   `json:"direct"`
	Dev             bool   `json:"dev"`
	Change          string `json:"change"`
	PreviousVersion string `json:"previous_version"`
	// Origin is declared or installed: where the manifest of the finding
	// found the package.
	Origin     string   `json:"origin,omitempty"`
	Licenses   []string `json:"licenses"`
	Deprecated bool     `json:"deprecated"`
	// DaysSincePublish is floor(days since the registry published the
	// version), as the cooldown control counts it.
	DaysSincePublish *int64                `json:"days_since_publish,omitempty"`
	Downloads        *int64                `json:"downloads,omitempty"`
	Scorecard        *float64              `json:"scorecard,omitempty"`
	LatestVersion    string                `json:"latest_version"`
	Vulnerabilities  []VulnerabilityInput  `json:"vulnerabilities"`
	Malware          *MalwareAnalysisInput `json:"malware,omitempty"`
}

// VulnerabilityInput is one advisory of a package.
type VulnerabilityInput struct {
	ID       string   `json:"id"`
	Aliases  []string `json:"aliases"`
	Severity string   `json:"severity"`
	CVSS     float64  `json:"cvss"`
}

// MalwareAnalysisInput is the Malysis verdict of a package.
type MalwareAnalysisInput struct {
	Malicious  bool   `json:"malicious"`
	Verified   bool   `json:"verified"`
	Confidence string `json:"confidence"`
}

// ManifestInput is the manifest of the finding.
type ManifestInput struct {
	Path      string `json:"path"`
	Ecosystem string `json:"ecosystem"`
	Kind      string `json:"kind"`
	Change    string `json:"change"`
}

// NewInput builds the input of a finding. pkg and m can be nil.
func NewInput(f *finding.Finding, pkg *model.Package, m *model.Manifest, now time.Time) Input {
	in := Input{Finding: FindingInput{
		ID: f.ID, ControlID: f.ControlID, Family: string(f.Family), Severity: string(f.Severity),
		Confidence: string(f.Confidence), Title: f.Title, Change: string(f.Change), SubjectKind: string(f.Subject.Kind),
	}}
	if f.Locus != nil {
		in.Finding.Path = f.Locus.Path
	}
	if m != nil {
		in.Manifest = ManifestInput{Path: m.Path, Ecosystem: string(m.Ecosystem), Kind: string(m.Kind), Change: string(m.Change)}
	}
	if pkg != nil {
		in.Package = packageInput(pkg, now)
		if m != nil {
			in.Package.Origin = string(m.Kind.Origin())
		}
	}
	return in
}

func packageInput(p *model.Package, now time.Time) *PackageInput {
	in := &PackageInput{
		PURL: p.ID.PURL(), Ecosystem: string(p.ID.Ecosystem()), Name: p.ID.Name(), Version: p.ID.Version(),
		RawName: p.ID.RawName(), RawVersion: p.ID.RawVersion(),
		Direct: p.Direct, Dev: p.Dev, Change: string(p.Change), PreviousVersion: p.PreviousVersion,
		Licenses: []string{}, Vulnerabilities: []VulnerabilityInput{},
	}
	if i := p.Insight; i != nil {
		in.Licenses = append(in.Licenses, i.Licenses...)
		in.Deprecated = i.Deprecated
		in.LatestVersion = i.LatestVersion
		if i.PublishedAt != nil {
			days := int64(now.Sub(*i.PublishedAt).Hours() / 24)
			in.DaysSincePublish = &days
		}
		if i.Downloads > 0 {
			in.Downloads = &i.Downloads
		}
		if i.Scorecard != nil {
			in.Scorecard = &i.Scorecard.Score
		}
		for _, v := range i.Vulnerabilities {
			aliases := append([]string{}, v.Aliases...)
			in.Vulnerabilities = append(in.Vulnerabilities, VulnerabilityInput{ID: v.ID, Aliases: aliases, Severity: v.Severity, CVSS: v.CVSS})
		}
	}
	if a := p.Malware; a != nil {
		in.Malware = &MalwareAnalysisInput{Malicious: a.Malicious, Verified: a.Verified, Confidence: a.Confidence}
	}
	return in
}

// activation returns the CEL variables of the input. The JSON form is the
// contract, so the schema and the variables cannot drift apart.
func (in Input) activation() (map[string]any, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return nil, fmt.Errorf("encode policy input: %w", err)
	}
	var vars map[string]any
	if err := json.Unmarshal(b, &vars); err != nil {
		return nil, fmt.Errorf("decode policy input: %w", err)
	}
	if _, ok := vars["package"]; !ok {
		vars["package"] = map[string]any{}
	}
	vars[packageIdent] = vars["package"]
	delete(vars, "package")
	return vars, nil
}
