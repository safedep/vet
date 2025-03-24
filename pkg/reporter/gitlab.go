package reporter

// GitLabReporter is the reporter for GitLab.
// This report is same for most of gitlab scanners, types
// and schemas.
// But we are using only for dependencyscanning report. That's we do report.type = "dependency_scanning"
// Schema: https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/raw/v15.2.1/dist/dependency-scanning-report-format.json

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
)

type GitLabReporterConfig struct {
	Path string // Report path
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

// GitLab backend requires time to be in this format
// Learned the hard way :), (not that actually , thanks to Cursor)
func formatTime(t time.Time) string {
	return t.Format("2006-01-02T15:04:05")
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

			// Create GitLab vulnerability entry
			glVuln := GitLabVulnerability{
				ID:          utils.SafelyGetValue(vulns[i].Id),
				Name:        utils.SafelyGetValue(vulns[i].Summary),
				Description: utils.SafelyGetValue(vulns[i].Summary), // Summary is good for names, but not for description, we need some more infor here
				Severity:    severity,
				// Todo: Solution
				// Solution:    "Upgrade to a newer version with the fix",
			}

			// Set location info
			glVuln.Location.File = manifest.Path
			glVuln.Location.Dependency.Package.Name = pkg.GetName()
			glVuln.Location.Dependency.Version = pkg.GetVersion()

			glVuln.Location.Dependency.Direct = pkg.Depth == 1

			// Add identifiers
			vulnId := utils.SafelyGetValue(vulns[i].Id)
			if vulnId != "" {
				glVuln.Identifiers = append(glVuln.Identifiers, struct {
					Type  string `json:"type"`
					Name  string `json:"name"`
					Value string `json:"value"`
					URL   string `json:"url"`
				}{
					Type:  "VULNERABILITY_ID",
					Name:  "VulnerabilityID",
					Value: vulnId,
					URL:   fmt.Sprintf("https://safedep.io/vulns/%s", vulnId), // Using a valid URL format
				})
			}

			r.vulnerabilities = append(r.vulnerabilities, glVuln)
		}
	}
}

func (r *gitLabReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {}

func (r *gitLabReporter) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *gitLabReporter) Finish() error {
	logger.Infof("Generating GitLab dependency scanning report: %s", r.config.Path)

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
	err = os.WriteFile(r.config.Path, jsonData, 0o644)
	if err != nil {
		return fmt.Errorf("failed to write GitLab report: %w", err)
	}

	return nil
}
