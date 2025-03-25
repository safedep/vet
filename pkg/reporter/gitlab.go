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

type GitLabReporterConfig struct {
	Path       string // Report path, value of --report-gitlab
	VetVersion string // Vet version, value from version.go
}

// GitLabVendor represents vendor information
type GitLabVendor struct {
	Name string `json:"name"`
}

// GitLabScanner represents scanner information
type GitLabScanner struct {
	ID      string       `json:"id"`
	Name    string       `json:"name"`
	Version string       `json:"version"`
	Vendor  GitLabVendor `json:"vendor"`
}

// GitLabPackage represents package information
type GitLabPackage struct {
	Name string `json:"name"`
}

// GitLabDependency represents dependency information
type GitLabDependency struct {
	Package GitLabPackage `json:"package"`
	Version string        `json:"version"`
	Direct  bool          `json:"direct"`
}

// GitLabLocation represents location information
type GitLabLocation struct {
	File       string           `json:"file"`
	Dependency GitLabDependency `json:"dependency"`
}

// GitLabIdentifier represents identifier information
type GitLabIdentifier struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	URL   string `json:"url"`
}

// GitLabVulnerability represents a vulnerability in GitLab format
// Docs: https://docs.gitlab.com/development/integrations/secure/#vulnerabilities
type GitLabVulnerability struct {
	ID          string             `json:"id"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Severity    string             `json:"severity"`
	Solution    string             `json:"solution"`
	Location    GitLabLocation     `json:"location"`
	Identifiers []GitLabIdentifier `json:"identifiers"`
}

// GitLabScan represents scan information
type GitLabScan struct {
	Scanner   GitLabScanner `json:"scanner"`
	Analyzer  GitLabScanner `json:"analyzer"` // Reusing GitLabScanner as they have same structure
	Type      string        `json:"type"`
	StartTime string        `json:"start_time"`
	EndTime   string        `json:"end_time"`
	Status    string        `json:"status"`
}

// GitLabReport represents the complete GitLab report currently using the 15.2.1 schema
// and `dependency_scanning` type.
// but can be extended to support other types and schemas in the future.
// docs: https://docs.gitlab.com/development/integrations/secure/#report
type GitLabReport struct {
	Schema          string                `json:"schema"`
	Version         string                `json:"version"`
	Scan            GitLabScan            `json:"scan"`
	Vulnerabilities []GitLabVulnerability `json:"vulnerabilities"`
}

type gitLabReporter struct {
	config          GitLabReporterConfig
	vulnerabilities []GitLabVulnerability
	startTime       time.Time
}

// Ensure gitLabReporter implements Reporter interface
var _ Reporter = (*gitLabReporter)(nil)

func NewGitLabReporter(config GitLabReporterConfig) (Reporter, error) {
	return &gitLabReporter{
		config:          config,
		vulnerabilities: make([]GitLabVulnerability, 0),
		startTime:       time.Now(),
	}, nil
}

func (r *gitLabReporter) Name() string {
	return "GitLab Dependency Scanning Report Generator"
}

// GitLab requires time to be in this format
// Learned the hard way :), (not that actually , thanks to Cursor)
func formatTime(t time.Time) string {
	return t.Format("2006-01-02T15:04:05")
}

// addIdentifiers adds all relevant identifiers for a vulnerability
// following GitLab's identifier guidelines
// Docs: https://docs.gitlab.com/development/integrations/secure/#identifiers
func addIdentifiers(vuln *GitLabVulnerability, vulnData *insightapi.PackageVulnerability) {
	// Extract identifiers from the vulnerability data
	var cves, cwes, ghsas []string
	aliases := utils.SafelyGetValue(vulnData.Aliases)

	for _, alias := range aliases {
		switch {
		case strings.HasPrefix(alias, "CVE-"):
			cves = append(cves, alias)
		case strings.HasPrefix(alias, "CWE-"):
			cwes = append(cwes, alias)
		case strings.HasPrefix(alias, "GHSA-"):
			ghsas = append(ghsas, alias)
		}
	}

	// Add identifiers in order of priority
	identifiers := make([]GitLabIdentifier, 0)

	// Add all CVEs first
	for _, cve := range cves {
		identifiers = append(identifiers, GitLabIdentifier{
			Type:  "cve",
			Name:  cve,
			Value: cve,
			URL:   fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cve),
		})
	}

	// Add all CWEs
	for _, cwe := range cwes {
		identifiers = append(identifiers, GitLabIdentifier{
			Type:  "cwe",
			Name:  cwe,
			Value: strings.TrimPrefix(cwe, "CWE-"),
			URL:   fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(cwe, "CWE-")),
		})
	}

	// Add all GHSAs
	for _, ghsa := range ghsas {
		identifiers = append(identifiers, GitLabIdentifier{
			Type:  "ghsa",
			Name:  ghsa,
			Value: strings.TrimPrefix(ghsa, "GHSA-"),
			URL:   fmt.Sprintf("https://github.com/advisories/%s", ghsa),
		})
	}

	// If identifiers are more than 20, then system saves only 20, so why increase the network cost
	if len(identifiers) > 20 {
		identifiers = identifiers[:20]
	}

	vuln.Identifiers = identifiers
}

func (r *gitLabReporter) AddManifest(manifest *models.PackageManifest) {
	// Process each package in the manifest
	for _, pkg := range manifest.Packages {
		if pkg.Insights == nil {
			continue
		}

		// Package location
		location := GitLabLocation{
			File: manifest.Path,
			Dependency: GitLabDependency{
				Package: GitLabPackage{
					Name: pkg.GetName(),
				},
				Version: pkg.GetVersion(),
				Direct:  pkg.Depth == 0,
			},
		}

		// Add malware analysis result
		malwareAnalysis := pkg.MalwareAnalysis

		if malwareAnalysis != nil && (malwareAnalysis.IsMalware || malwareAnalysis.IsSuspicious) {
			severity := "Critical"
			if malwareAnalysis.IsSuspicious {
				severity = "High"
			}

			description := ""
			solution := ""
			reportUrl := ""

			if malwareAnalysis.Report != nil {
				reportUrl = malysis.ReportURL(malwareAnalysis.Report.ReportId)
				if malwareAnalysis.Report.Inference != nil {
					description = malwareAnalysis.Report.Inference.Summary
					solution = malwareAnalysis.Report.Inference.Details
				}
			}

			malwareId := fmt.Sprintf("MAL-%s", malwareAnalysis.AnalysisId)
			glVuln := GitLabVulnerability{
				ID:          malwareId,
				Name:        fmt.Sprintf("%s@%s is Malware/Suspicious Package", pkg.GetName(), pkg.GetVersion()),
				Description: description,
				Severity:    severity,
				Location:    location,
				Identifiers: []GitLabIdentifier{
					{
						Type:  "malware",
						Name:  malwareId,
						Value: malwareId,
						URL:   reportUrl,
					},
				},
				Solution: solution,
			}

			r.vulnerabilities = append(r.vulnerabilities, glVuln)
		}

		// Convert each vulnerability to GitLab format
		vulns := utils.SafelyGetValue(pkg.Insights.Vulnerabilities)
		for i := range vulns {
			// Map severity
			severity := "Unknown"
			severities := utils.SafelyGetValue(vulns[i].Severities)
			if len(severities) > 0 {
				risk := utils.SafelyGetValue(severities[0].Risk)
				switch risk {
				case insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL:
					severity = "Critical"
				case insightapi.PackageVulnerabilitySeveritiesRiskHIGH:
					severity = "High"
				case insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM:
					severity = "Medium"
				case insightapi.PackageVulnerabilitySeveritiesRiskLOW:
					severity = "Low"
				}
			}

			summary := utils.SafelyGetValue(vulns[i].Summary)
			// Create GitLab vulnerability entry
			glVuln := GitLabVulnerability{
				ID:          utils.SafelyGetValue(vulns[i].Id),
				Name:        summary,
				Description: summary, // Using summary as description since that's what we have
				Severity:    severity,
				Location:    location,
				// Todo: Solution
				// Solution:    fmt.Sprintf("Upgrade to a version without %s", utils.SafelyGetValue(vulns[i].Id)),
			}

			// Add all relevant identifiers
			addIdentifiers(&glVuln, &vulns[i])

			r.vulnerabilities = append(r.vulnerabilities, glVuln)
		}
	}
}

func (r *gitLabReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {}

func (r *gitLabReporter) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *gitLabReporter) Finish() error {
	vendor := GitLabVendor{Name: "safedep"}
	scanner := GitLabScanner{
		ID:      "vet",
		Name:    "vet",
		Version: r.config.VetVersion,
		Vendor:  vendor,
	}

	report := GitLabReport{
		Schema:  "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/15.2.1/dist/dependency-scanning-report-format.json",
		Version: "15.2.1",
		Scan: GitLabScan{
			Scanner:   scanner,
			Analyzer:  scanner, // Using same scanner info for analyzer
			Type:      "dependency_scanning",
			StartTime: formatTime(r.startTime),
			EndTime:   formatTime(time.Now()),
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
