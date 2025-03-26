package reporter

// GitLabReporter is the reporter for GitLab.
// This report is same for most of gitlab scanners, types
// and schemas.
// But we are using only for dependency_scanning report. That's we do report.type = "dependency_scanning"
// Schema: https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v15.2.1/dist/dependency-scanning-report-format.json
// Docs: https://www.notion.so/safedep-inc/Need-for-GitLab-specific-schema-reporting-1c061d70b23680319849c32d2b0cbcd6?pvs=4

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/malysis"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
)

// gitlabMaxIdentifiers is the maximum number of identifiers that can be added to a vulnerability
// Docs: https://docs.gitlab.com/development/integrations/secure/#identifiers
const gitlabMaxIdentifiers = 20

type GitLabReporterConfig struct {
	Path       string // Report path, value of --report-gitlab
	VetVersion string // Vet version, value from version.go
}

// gitLabVendor represents vendor information
type gitLabVendor struct {
	Name string `json:"name"`
}

// gitLabScanner represents scanner information
type gitLabScanner struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Version string       `json:"version"`
	Vendor  gitLabVendor `json:"vendor"`
}

// gitLabPackage represents package information
type gitLabPackage struct {
	Name string `json:"name"`
}

// gitLabDependency represents dependency information
type gitLabDependency struct {
	Package gitLabPackage `json:"package"`
	Version string        `json:"version"`
	Direct  bool          `json:"direct"`
}

// gitLabLocation represents location information
type gitLabLocation struct {
	File       string           `json:"file"`
	Dependency gitLabDependency `json:"dependency"`
}

// gitLabIdentifierType represents type of identifier
// Docs: https://docs.gitlab.com/development/integrations/secure/#identifiers
type gitLabIdentifierType string

const (
	gitLabIdentifierTypeCVE       gitLabIdentifierType = "cve"
	gitLabIdentifierTypeCWE       gitLabIdentifierType = "cwe"
	gitLabIdentifierTypeGHSA      gitLabIdentifierType = "ghsa"
	gitLabIdentifierTypeELSA      gitLabIdentifierType = "elsa"
	gitLabIdentifierTypeOSVD      gitLabIdentifierType = "osvdb"
	gitLabIdentifierTypeOWASP     gitLabIdentifierType = "owasp"
	gitLabIdentifierTypeRHSA      gitLabIdentifierType = "rhsa"
	gitLabIdentifierTypeUSN       gitLabIdentifierType = "usn"
	gitLabIdentifierTypeHACKERONE gitLabIdentifierType = "hackerone"
	// NOT GITLAB BUT WE ARE USING THIS FOR OUR CUSTOM IDENTIFIER
	gitLabIdentifierTypeMALWARE gitLabIdentifierType = "malware"
)

// gitLabIdentifier represents identifier information
type gitLabIdentifier struct {
	Type  gitLabIdentifierType `json:"type"`
	Name  string               `json:"name"`
	Value string               `json:"value"`
	URL   string               `json:"url"`
}

// Severity represents severity of a vulnerability or malware
type Severity string

const (
	SeverityUnknown  Severity = "Unknown"
	SeverityCritical Severity = "Critical"
	SeverityHigh     Severity = "High"
	SeverityMedium   Severity = "Medium"
	SeverityLow      Severity = "Low"
)

// gitLabVulnerability represents a vulnerability in GitLab format
// Docs: https://docs.gitlab.com/development/integrations/secure/#vulnerabilities
type gitLabVulnerability struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Severity    Severity           `json:"severity"`
	Solution    string             `json:"solution"`
	Location    gitLabLocation     `json:"location"`
	Identifiers []gitLabIdentifier `json:"identifiers"`
}

// gitLabScan represents scan information
type gitLabScan struct {
	Scanner   gitLabScanner `json:"scanner"`
	Analyzer  gitLabScanner `json:"analyzer"` // Reusing GitLabScanner as they have same structure
	Type      string        `json:"type"`
	StartTime string        `json:"start_time"`
	EndTime   string        `json:"end_time"`
	Status    string        `json:"status"`
}

// gitLabReport represents the complete GitLab report currently using the 15.2.1 schema
// and `dependency_scanning` type.
// but can be extended to support other types and schemas in the future.
// docs: https://docs.gitlab.com/development/integrations/secure/#report
type gitLabReport struct {
	Schema          string                `json:"schema"`
	Version         string                `json:"version"`
	Scan            gitLabScan            `json:"scan"`
	Vulnerabilities []gitLabVulnerability `json:"vulnerabilities"`
}

type gitLabReporter struct {
	config          GitLabReporterConfig
	vulnerabilities []gitLabVulnerability
	startTime       time.Time
}

// Ensure gitLabReporter implements Reporter interface
var _ Reporter = (*gitLabReporter)(nil)

func NewGitLabReporter(config GitLabReporterConfig) (Reporter, error) {
	return &gitLabReporter{
		config:          config,
		vulnerabilities: make([]gitLabVulnerability, 0),
		startTime:       time.Now(),
	}, nil
}

func (r *gitLabReporter) Name() string {
	return "GitLab Dependency Scanning Report Generator"
}

// GitLab requires time to be in pattern
// "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}$"
// Example: "2020-01-28T03:26:02"
//
// Docs (Schema Reference): https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/blob/master/dist/sast-report-format.json#L497
func gitlabFormatTime(t time.Time) string {
	return t.Format("2006-01-02T15:04:05")
}

// gitlabAddVulnerabilityIdentifiers adds all relevant identifiers for a vulnerability
// following GitLab's identifier guidelines
// Docs: https://docs.gitlab.com/development/integrations/secure/#identifiers
func gitlabAddVulnerabilityIdentifiers(vuln *gitLabVulnerability, vulnData *insightapi.PackageVulnerability) {
	// Extract identifiers from the vulnerability data
	identifiersFound := make(map[gitLabIdentifierType][]string)
	aliases := utils.SafelyGetValue(vulnData.Aliases)

	for _, alias := range aliases {
		switch {
		case strings.HasPrefix(alias, "CVE-"):
			identifiersFound[gitLabIdentifierTypeCVE] = append(identifiersFound[gitLabIdentifierTypeCVE], alias)
		case strings.HasPrefix(alias, "CWE-"):
			identifiersFound[gitLabIdentifierTypeCWE] = append(identifiersFound[gitLabIdentifierTypeCWE], alias)
		case strings.HasPrefix(alias, "GHSA-"):
			identifiersFound[gitLabIdentifierTypeGHSA] = append(identifiersFound[gitLabIdentifierTypeGHSA], alias)
		case strings.HasPrefix(alias, "ELSA-"):
			identifiersFound[gitLabIdentifierTypeELSA] = append(identifiersFound[gitLabIdentifierTypeELSA], alias)
		case strings.HasPrefix(alias, "OSVDB-"):
			identifiersFound[gitLabIdentifierTypeOSVD] = append(identifiersFound[gitLabIdentifierTypeOSVD], alias)
		case strings.HasPrefix(alias, "OWASP-"):
			identifiersFound[gitLabIdentifierTypeOWASP] = append(identifiersFound[gitLabIdentifierTypeOWASP], alias)
		case strings.HasPrefix(alias, "RHSA-"):
			identifiersFound[gitLabIdentifierTypeRHSA] = append(identifiersFound[gitLabIdentifierTypeRHSA], alias)
		case strings.HasPrefix(alias, "USN-"):
			identifiersFound[gitLabIdentifierTypeUSN] = append(identifiersFound[gitLabIdentifierTypeUSN], alias)
		case strings.HasPrefix(alias, "HACKERONE-"):
			identifiersFound[gitLabIdentifierTypeHACKERONE] = append(identifiersFound[gitLabIdentifierTypeHACKERONE], alias)
		}
	}

	// Priority order of identifiers
	// Since we can only who {gitlabMaxIdentifiers} in gitlab, we need to prioritize identifiers
	identifiersPriority := []struct {
		identifierType gitLabIdentifierType
		urlPrefix      string
		namePrefix     string
		trimNamePrefix bool // For some url, we need to trim the name prefix, like GitHub Advisories
	}{
		{gitLabIdentifierTypeCVE, "https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", "CVE", false},
		{gitLabIdentifierTypeCWE, "https://cwe.mitre.org/data/definitions/%s.html", "CWE", true}, // Trim CWE- from the identifier name
		{gitLabIdentifierTypeGHSA, "https://github.com/advisories/%s", "GHSA", true},             // Trim GHSA- from the identifier name
		{gitLabIdentifierTypeELSA, "https://linux.oracle.com/errata/%s.html", "ELSA", false},
		{gitLabIdentifierTypeOSVD, "https://osv.dev/vulnerability/%s", "OSVDB", false},
		{gitLabIdentifierTypeOWASP, "https://owasp.org/www-community/vulnerabilities/%s", "OWASP", false},
		{gitLabIdentifierTypeRHSA, "https://access.redhat.com/errata/%s", "RHSA", false},
		{gitLabIdentifierTypeUSN, "https://ubuntu.com/security/notices/%s", "USN", false},
		{gitLabIdentifierTypeHACKERONE, "https://hackerone.com/reports/%s", "HACKERONE", false},
	}

	// Add identifiers in order of priority to report
	reportIdentifiers := make([]gitLabIdentifier, 0)

	for _, idx := range identifiersPriority {
		for _, identifier := range identifiersFound[idx.identifierType] {
			value := identifier
			if idx.trimNamePrefix {
				value = strings.TrimPrefix(identifier, fmt.Sprintf("%s-", idx.namePrefix)) // Trim CWE- or GHSA- etc. from the identifier name
			}

			reportIdentifiers = append(reportIdentifiers, gitLabIdentifier{
				Type:  idx.identifierType,
				Name:  identifier,
				Value: value,
				URL:   fmt.Sprintf(idx.urlPrefix, value),
			})
		}
	}

	// If identifiers are more than {gitlabMaxIdentifiers}, then system saves only {gitlabMaxIdentifiers}, so why increase the network cost
	if len(reportIdentifiers) > gitlabMaxIdentifiers {
		reportIdentifiers = reportIdentifiers[:gitlabMaxIdentifiers]
	}

	vuln.Identifiers = reportIdentifiers
}

func (r *gitLabReporter) AddManifest(manifest *models.PackageManifest) {
	// Process each package in the manifest
	for _, pkg := range manifest.Packages {
		if pkg.Insights == nil {
			continue
		}

		// Package location
		location := gitLabLocation{
			File: manifest.Path,
			Dependency: gitLabDependency{
				Package: gitLabPackage{
					Name: pkg.GetName(),
				},
				Version: pkg.GetVersion(),
				Direct:  pkg.IsDirect(),
			},
		}

		// Add malware analysis result
		malwareAnalysis := pkg.MalwareAnalysis

		if malwareAnalysis != nil && (malwareAnalysis.IsMalware || malwareAnalysis.IsSuspicious) {
			severity := SeverityCritical
			if malwareAnalysis.IsSuspicious {
				severity = SeverityHigh
			}

			description := ""
			reportUrl := ""

			if malwareAnalysis.Report != nil {
				reportUrl = malysis.ReportURL(malwareAnalysis.Report.ReportId)
				if malwareAnalysis.Report.Inference != nil {
					description = fmt.Sprintf("%s\n\n%s", malwareAnalysis.Report.Inference.Summary, malwareAnalysis.Report.Inference.Details)
				}
			}

			malwareId := fmt.Sprintf("MAL-%s", malwareAnalysis.AnalysisId)
			glVuln := gitLabVulnerability{
				ID:          malwareId,
				Name:        fmt.Sprintf("%s@%s is Malware/Suspicious Package", pkg.GetName(), pkg.GetVersion()),
				Description: description,
				Severity:    severity,
				Location:    location,
				Identifiers: []gitLabIdentifier{
					{
						Type:  gitLabIdentifierTypeMALWARE,
						Name:  malwareId,
						Value: malwareId,
						URL:   reportUrl,
					},
				},
				// TODO
				// Solution: "",
			}

			r.vulnerabilities = append(r.vulnerabilities, glVuln)
		}

		// Convert each vulnerability to GitLab format
		vulns := utils.SafelyGetValue(pkg.Insights.Vulnerabilities)
		for i := range vulns {
			// Map severity
			severity := SeverityUnknown
			severities := utils.SafelyGetValue(vulns[i].Severities)
			if len(severities) > 0 {
				risk := utils.SafelyGetValue(severities[0].Risk)
				severity = getVulnerabilitySeverity(risk)
			}

			summary := utils.SafelyGetValue(vulns[i].Summary)
			// Create GitLab vulnerability entry
			glVuln := gitLabVulnerability{
				ID:          utils.SafelyGetValue(vulns[i].Id),
				Name:        summary,
				Description: summary, // Using summary as description since that's what we have
				Severity:    severity,
				Location:    location,
				// Todo: Solution
				// Solution:    fmt.Sprintf("Upgrade to a version without %s", utils.SafelyGetValue(vulns[i].Id)),
			}

			// Add all relevant identifiers
			gitlabAddVulnerabilityIdentifiers(&glVuln, &vulns[i])

			r.vulnerabilities = append(r.vulnerabilities, glVuln)
		}
	}
}

func (r *gitLabReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {}

func (r *gitLabReporter) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *gitLabReporter) Finish() error {
	vendor := gitLabVendor{Name: "safedep"}
	scanner := gitLabScanner{
		ID:      "vet",
		Name:    "vet",
		Version: r.config.VetVersion,
		Vendor:  vendor,
	}

	report := gitLabReport{
		Schema:  "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/15.2.1/dist/dependency-scanning-report-format.json",
		Version: "15.2.1",
		Scan: gitLabScan{
			Scanner:   scanner,
			Analyzer:  scanner, // Using same scanner info for analyzer
			Type:      "dependency_scanning",
			StartTime: gitlabFormatTime(r.startTime),
			EndTime:   gitlabFormatTime(time.Now()),
			Status:    "success",
		},
		Vulnerabilities: r.vulnerabilities,
	}

	// Marshal to JSON
	jsonData, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal GitLab report: %w", err)
	}

	// Write to file
	err = os.WriteFile(r.config.Path, jsonData, os.ModePerm)
	if err != nil {
		return fmt.Errorf("failed to write GitLab report: %w", err)
	}

	return nil
}

func getVulnerabilitySeverity(risk insightapi.PackageVulnerabilitySeveritiesRisk) Severity {
	switch risk {
	case insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL:
		return SeverityCritical
	case insightapi.PackageVulnerabilitySeveritiesRiskHIGH:
		return SeverityHigh
	case insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM:
		return SeverityMedium
	case insightapi.PackageVulnerabilitySeveritiesRiskLOW:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}
