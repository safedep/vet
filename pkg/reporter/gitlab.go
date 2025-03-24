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
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
)

type GitLabReporterConfig struct {
	Path string // Report path, value of --report-gitlab
}

// GitLabVulnerability is the struct for the GitLab vulnerability,
// it is used to convert the vulnerability to the GitLab format.
// Docs: https://docs.gitlab.com/development/integrations/secure/#vulnerabilities
type GitLabVulnerability struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Solution    string `json:"solution"`
	Location    struct {
		File       string `json:"file"`
		Dependency struct {
			Package struct {
				Name string `json:"name"`
			} `json:"package"`
			Version string `json:"version"`
			Direct  bool   `json:"direct"`
		} `json:"dependency"`
	} `json:"location"`
	Identifiers []struct {
		Type  string `json:"type"`
		Name  string `json:"name"`
		Value string `json:"value"`
		URL   string `json:"url"`
	} `json:"identifiers"`
}

// GitLabReport is the struct for the GitLab, currently using the 15.2.1 schema
// and `dependency_scanning` type.
// but can be extended to support other types and schemas in the future.
// docs: https://docs.gitlab.com/development/integrations/secure/#report
type GitLabReport struct {
	Schema  string `json:"schema"`
	Version string `json:"version"`
	Scan    struct {
		Scanner struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Vendor  struct {
				Name string `json:"name"`
			} `json:"vendor"`
		} `json:"scanner"`
		Analyzer struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Version string `json:"version"`
			Vendor  struct {
				Name string `json:"name"`
			} `json:"vendor"`
		} `json:"analyzer"`
		Type      string `json:"type"`
		StartTime string `json:"start_time"`
		EndTime   string `json:"end_time"`
		Status    string `json:"status"`
	} `json:"scan"`
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
	var cve, cwe, ghsa string
	aliases := utils.SafelyGetValue(vulnData.Aliases)
	for _, alias := range aliases {
		switch {
		case strings.HasPrefix(alias, "CVE-"):
			cve = alias
		case strings.HasPrefix(alias, "CWE-"):
			cwe = alias
		case strings.HasPrefix(alias, "GHSA-"):
			ghsa = alias
		}
	}

	// Add identifiers in order of priority (max 20 as per GitLab's limit)
	identifiers := make([]struct {
		Type  string `json:"type"`
		Name  string `json:"name"`
		Value string `json:"value"`
		URL   string `json:"url"`
	}, 0)

	// Primary identifier should be CVE if available
	if cve != "" {
		identifiers = append(identifiers, struct {
			Type  string `json:"type"`
			Name  string `json:"name"`
			Value string `json:"value"`
			URL   string `json:"url"`
		}{
			Type:  "cve",
			Name:  cve,
			Value: cve,
			URL:   fmt.Sprintf("https://cve.mitre.org/cgi-bin/cvename.cgi?name=%s", cve),
		})
	}

	// Add CWE if available
	if cwe != "" {
		identifiers = append(identifiers, struct {
			Type  string `json:"type"`
			Name  string `json:"name"`
			Value string `json:"value"`
			URL   string `json:"url"`
		}{
			Type:  "cwe",
			Name:  cwe,
			Value: strings.TrimPrefix(cwe, "CWE-"),
			URL:   fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(cwe, "CWE-")),
		})
	}

	// Add GHSA if available
	if ghsa != "" {
		identifiers = append(identifiers, struct {
			Type  string `json:"type"`
			Name  string `json:"name"`
			Value string `json:"value"`
			URL   string `json:"url"`
		}{
			Type:  "ghsa",
			Name:  ghsa,
			Value: strings.TrimPrefix(ghsa, "GHSA-"),
			URL:   fmt.Sprintf("https://github.com/advisories/%s", ghsa),
		})
	}

	// Limit to 20 identifiers as per GitLab's requirement
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
				// Todo: Solution
				// Solution:    fmt.Sprintf("Upgrade to a version without %s", utils.SafelyGetValue(vulns[i].Id)),
			}

			// Set location info
			glVuln.Location.File = manifest.Path
			glVuln.Location.Dependency.Package.Name = pkg.GetName()
			glVuln.Location.Dependency.Version = pkg.GetVersion()
			glVuln.Location.Dependency.Direct = pkg.Depth == 0

			// Add all relevant identifiers
			addIdentifiers(&glVuln, &vulns[i])

			r.vulnerabilities = append(r.vulnerabilities, glVuln)
		}
	}
}

func (r *gitLabReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {}

func (r *gitLabReporter) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *gitLabReporter) Finish() error {
	report := GitLabReport{
		Schema:  "https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/15.2.1/dist/dependency-scanning-report-format.json",
		Version: "15.2.1",
	}

	// Set scanner info
	report.Scan.Scanner.ID = "vet"
	report.Scan.Scanner.Name = "vet"
	report.Scan.Scanner.Version = "latest"
	report.Scan.Scanner.Vendor.Name = "safedep"

	// Set analyzer info (required by schema)
	report.Scan.Analyzer.ID = "vet"
	report.Scan.Analyzer.Name = "vet"
	report.Scan.Analyzer.Version = "latest"
	report.Scan.Analyzer.Vendor.Name = "safedep"

	// Set scan metadata
	report.Scan.Type = "dependency_scanning"
	report.Scan.StartTime = formatTime(r.startTime)
	report.Scan.EndTime = formatTime(time.Now())
	report.Scan.Status = "success"

	// Add vulnerabilities
	report.Vulnerabilities = r.vulnerabilities

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
