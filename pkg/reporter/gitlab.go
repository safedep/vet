package reporter

// GitLabReporter is the reporter for GitLab.
// This report is same for most of gitlab scanners, types
// and schemas.
//
// We are using Schema Version 15.2.1 for dependency_scanning report.
// All the versions are available at: https://gitlab.com/gitlab-org/security-products/security-report-schemas

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common"
	"github.com/safedep/vet/pkg/malysis"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
)

// gitlab constants
// Docs: https://docs.gitlab.com/development/integrations/secure/#identifiers
const (
	gitlabMaxIdentifiers               = 20 //  maximum number of identifiers that can be added to a vulnerability
	gitlabReportTypeDependencyScanning = "dependency_scanning"
	gitlabSchemaURL                    = "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/15.2.1/dist/dependency-scanning-report-format.json"
	gitlabSchemaVersion                = "15.2.1"
	gitlabSuccessStatus                = "success"
	gitlabFailedStatus                 = "failure"
	gitlabPolicyViolationSeverity      = SeverityInfo // Default severity for policy violations
	// SafeDep Custom - Not Standard GitLab Type
	gitlabCustomPolicyType          = "policy"
	gitlabCustomPolicySuffix        = "POL"
	gitlabCustomPolicyIdentifierURL = "https://docs.safedep.io/advanced/policy-as-code"
)

type GitLabReporterConfig struct {
	Path string // Report path, value of --report-gitlab
	Tool ToolMetadata
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
	gitLabIdentifierTypeCVE  gitLabIdentifierType = "cve"
	gitLabIdentifierTypeCWE  gitLabIdentifierType = "cwe"
	gitLabIdentifierTypeGHSA gitLabIdentifierType = "ghsa"
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
	SeverityInfo     Severity = "Info"
)

// gitLabVulnerability represents a vulnerability in GitLab format
// Docs: https://docs.gitlab.com/development/integrations/secure/#vulnerabilities
type gitLabVulnerability struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Severity    Severity           `json:"severity"`
	Location    gitLabLocation     `json:"location"`
	Solution    string             `json:"solution"`
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

func NewGitLabReporter(config GitLabReporterConfig) (*gitLabReporter, error) {
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
func (r *gitLabReporter) gitlabFormatTime(t time.Time) string {
	return t.Format("2006-01-02T15:04:05")
}

// gitlabAddVulnerabilityIdentifiers adds all relevant identifiers for a vulnerability
// following GitLab's identifier guidelines
// Docs: https://docs.gitlab.com/development/integrations/secure/#identifiers
func (r *gitLabReporter) gitlabAddVulnerabilityIdentifiers(vuln *gitLabVulnerability, vulnData *insightapi.PackageVulnerability) {
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
		}
	}

	// Priority order of identifiers
	// Since we can only who {gitlabMaxIdentifiers} in gitlab, we need to prioritize identifiers
	identifiersPriority := []gitLabIdentifierType{
		gitLabIdentifierTypeCVE,
		gitLabIdentifierTypeCWE,
		gitLabIdentifierTypeGHSA,
	}

	// Add identifiers in order of priority to report
	reportIdentifiers := make([]gitLabIdentifier, 0)

	for _, idfsType := range identifiersPriority {
		for _, identifier := range identifiersFound[idfsType] {
			url := ""
			switch idfsType {
			case gitLabIdentifierTypeCVE:
				url = common.GetCveReferenceURL(identifier)
			case gitLabIdentifierTypeCWE:
				url = common.GetCweReferenceURL(identifier)
			case gitLabIdentifierTypeGHSA:
				url = common.GetGhsaReferenceURL(identifier)
			}

			reportIdentifiers = append(reportIdentifiers, gitLabIdentifier{
				Type:  idfsType,
				Name:  identifier,
				Value: identifier,
				URL:   url,
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

			description := "Package is malware/suspicious"
			reportUrl := ""

			if malwareAnalysis.Report != nil {
				reportUrl = malysis.ReportURL(malwareAnalysis.Report.ReportId)
				description = fmt.Sprintf("%s\n\n%s", malwareAnalysis.Report.GetInference().GetSummary(), malwareAnalysis.Report.GetInference().GetDetails())
			}

			glVuln := gitLabVulnerability{
				ID:          malwareAnalysis.Id(),
				Name:        fmt.Sprintf("%s@%s is malware/suspicious package", pkg.GetName(), pkg.GetVersion()),
				Description: description,
				Severity:    severity,
				Location:    location,
				Identifiers: []gitLabIdentifier{
					{
						Type:  gitLabIdentifierTypeMALWARE,
						Name:  malwareAnalysis.Id(),
						Value: malwareAnalysis.Id(),
						URL:   reportUrl,
					},
				},
			}

			r.vulnerabilities = append(r.vulnerabilities, glVuln)
		}

		// Convert each vulnerability to GitLab format
		vulns := utils.SafelyGetValue(pkg.Insights.Vulnerabilities)
		for _, vuln := range vulns {
			// Map severity
			severity := SeverityUnknown
			severities := utils.SafelyGetValue(vuln.Severities)
			if len(severities) > 0 {
				risk := utils.SafelyGetValue(severities[0].Risk)
				severity = r.getVulnerabilitySeverity(risk)
			}

			summary := utils.SafelyGetValue(vuln.Summary)
			// Summary can be null, so we need to set a default value
			// https://github.com/safedep/vet/pull/441#issuecomment-2768286240
			if summary == "" {
				summary = fmt.Sprintf("Vulnerability in %s", pkg.GetName())
			}

			// Create GitLab vulnerability entry
			glVuln := gitLabVulnerability{
				ID:          utils.SafelyGetValue(vuln.Id),
				Name:        summary,
				Description: r.getGitLabVulnerabilityDescription(pkg, summary),
				Severity:    severity,
				Location:    location,
				Solution:    r.getGitLabVulnerabilitySolution(pkg),
			}

			// Add all relevant identifiers
			r.gitlabAddVulnerabilityIdentifiers(&glVuln, &vuln)

			r.vulnerabilities = append(r.vulnerabilities, glVuln)
		}
	}
}

func (r *gitLabReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	if !event.IsFilterMatch() {
		return
	}

	if event.Package == nil || event.Filter == nil {
		return
	}

	// Create location information
	location := gitLabLocation{
		File: event.Package.Manifest.Path,
		Dependency: gitLabDependency{
			Package: gitLabPackage{
				Name: event.Package.GetName(),
			},
			Version: event.Package.GetVersion(),
			Direct:  event.Package.IsDirect(),
		},
	}

	policyViolId := fmt.Sprintf("%s-%s", gitlabCustomPolicySuffix, event.Package.Id())

	// Create a vulnerability entry for the policy violation
	glVuln := gitLabVulnerability{
		ID:   policyViolId,
		Name: fmt.Sprintf("Policy Violation by %s, %s", event.Package.GetName(), event.Filter.GetName()),
		Description: fmt.Sprintf("%s \n\n %s \n\n The CEL expression is:  \n\n ```yaml\n%s\n```\n\n",
			event.Filter.GetSummary(),
			event.Filter.GetDescription(),
			event.Filter.GetValue(),
		),
		Severity: gitlabPolicyViolationSeverity,
		Location: location,
		Solution: r.getPolicyViolationSolution(event),
		// This is no need to have identifiers for policy violations
		// but its required by gitlab schema
		Identifiers: []gitLabIdentifier{
			{
				Type:  gitlabCustomPolicyType,
				Name:  policyViolId,
				Value: policyViolId,
				URL:   gitlabCustomPolicyIdentifierURL,
			},
		},
	}

	r.vulnerabilities = append(r.vulnerabilities, glVuln)
}

func (r *gitLabReporter) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *gitLabReporter) Finish() error {
	vendor := gitLabVendor{Name: r.config.Tool.VendorName}
	scanner := gitLabScanner{
		ID:      r.config.Tool.Name,
		Name:    r.config.Tool.Name,
		Version: r.config.Tool.Version,
		Vendor:  vendor,
	}

	report := gitLabReport{
		Schema:  gitlabSchemaURL,
		Version: gitlabSchemaVersion,
		Scan: gitLabScan{
			Scanner:   scanner,
			Analyzer:  scanner, // Using same scanner info for analyzer
			Type:      gitlabReportTypeDependencyScanning,
			StartTime: r.gitlabFormatTime(r.startTime),
			EndTime:   r.gitlabFormatTime(time.Now()),
			Status:    gitlabSuccessStatus,
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

func (r *gitLabReporter) getVulnerabilitySeverity(risk insightapi.PackageVulnerabilitySeveritiesRisk) Severity {
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

// getVulnerabilityDescription returns the description for a vulnerability
// Markdown formatted
func (r *gitLabReporter) getGitLabVulnerabilityDescription(pkg *models.Package, summary string) string {
	pkgName := pkg.GetName()
	pkgVersion := pkg.GetVersion()

	description := fmt.Sprintf("Package **`%s@%s`**\n\n%s",
		pkgName,
		pkgVersion,
		summary)

	return description
}

// getVulnerabilitySolution returns the solution for a vulnerability
// Markdown formatted
func (r *gitLabReporter) getGitLabVulnerabilitySolution(pkg *models.Package) string {
	return getVulnerabilitySolution(pkg)
}

func (r *gitLabReporter) getPolicyViolationSolution(event *analyzer.AnalyzerEvent) string {
	return getPolicyViolationSolution(event)
}
