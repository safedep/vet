package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/common/utils"
	"github.com/safedep/vet/pkg/malysis"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func getGitLabReporter(reportPath string) (Reporter, error) {
	return NewGitLabReporter(GitLabReporterConfig{
		Path:           reportPath,
		ToolVersion:    "1.0.0",
		ToolName:       "vet",
		ToolVendorName: "safedep",
	})
}

func TestGitLabReporter(t *testing.T) {
	// Create a temporary directory for test reports
	tmpDir, err := os.MkdirTemp("", "gitlab-reporter-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	reportPath := filepath.Join(tmpDir, "gl-dependency-scanning-report.json")

	t.Run("NewGitLabReporter", func(t *testing.T) {
		reporter, err := getGitLabReporter(reportPath)
		assert.NoError(t, err)
		assert.NotNil(t, reporter)
		assert.Equal(t, "GitLab Dependency Scanning Report Generator", reporter.Name())
	})

	t.Run("Empty Report", func(t *testing.T) {
		reporter, err := getGitLabReporter(reportPath)
		assert.NoError(t, err)
		err = reporter.Finish()
		assert.NoError(t, err)

		// Read and verify the report
		data, err := os.ReadFile(reportPath)
		assert.NoError(t, err)

		var report gitLabReport
		err = json.Unmarshal(data, &report)
		assert.NoError(t, err)

		// Verify basic report structure
		assert.Equal(t, "15.2.1", report.Version)
		assert.Equal(t, "dependency_scanning", report.Scan.Type)
		assert.Equal(t, "vet", report.Scan.Scanner.ID)
		assert.Equal(t, "safedep", report.Scan.Scanner.Vendor.Name)
		assert.Empty(t, report.Vulnerabilities)
	})

	t.Run("Report With Vulnerabilities", func(t *testing.T) {
		reporter, err := getGitLabReporter(reportPath)
		assert.NoError(t, err)

		// Create test manifest with vulnerabilities
		manifest := &models.PackageManifest{
			Path: "test/package.json",
			Packages: []*models.Package{
				{
					PackageDetails: models.NewPackageDetail("npm", "test-package", "1.0.0"),
					Insights: &insightapi.PackageVersionInsight{
						Vulnerabilities: &[]insightapi.PackageVulnerability{
							{
								Id: utils.StringPtr("VULN-123"),
								Aliases: &[]string{
									"CVE-2023-1234",
									"CWE-79",
									"GHSA-abcd-efgh-ijkl",
								},
								Summary: utils.StringPtr("Test vulnerability"),
								Severities: &[]struct {
									Risk  *insightapi.PackageVulnerabilitySeveritiesRisk `json:"risk,omitempty"`
									Score *string                                        `json:"score,omitempty"`
									Type  *insightapi.PackageVulnerabilitySeveritiesType `json:"type,omitempty"`
								}{
									{
										Risk: (*insightapi.PackageVulnerabilitySeveritiesRisk)(utils.StringPtr("HIGH")),
									},
								},
							},
						},
					},
				},
			},
		}

		reporter.AddManifest(manifest)
		err = reporter.Finish()
		assert.NoError(t, err)

		// Read and verify the report
		data, err := os.ReadFile(reportPath)
		assert.NoError(t, err)

		var report gitLabReport
		err = json.Unmarshal(data, &report)
		assert.NoError(t, err)

		// Verify vulnerabilities
		assert.Len(t, report.Vulnerabilities, 1)
		vuln := report.Vulnerabilities[0]

		// Check basic vulnerability info
		assert.Equal(t, "VULN-123", vuln.ID)
		assert.Equal(t, "Test vulnerability", vuln.Name)
		assert.Equal(t, SeverityHigh, vuln.Severity)

		// Check location info
		assert.Equal(t, "test/package.json", vuln.Location.File)
		assert.Equal(t, "test-package", vuln.Location.Dependency.Package.Name)
		assert.Equal(t, "1.0.0", vuln.Location.Dependency.Version)
		assert.True(t, vuln.Location.Dependency.Direct)

		// Check identifiers (should be in priority order: CVE, CWE, GHSA)
		assert.GreaterOrEqual(t, len(vuln.Identifiers), 3)

		// Check CVE identifier
		assert.Equal(t, gitLabIdentifierTypeCVE, vuln.Identifiers[0].Type)
		assert.Equal(t, "CVE-2023-1234", vuln.Identifiers[0].Name)
		assert.Equal(t, "CVE-2023-1234", vuln.Identifiers[0].Value)
		assert.Contains(t, vuln.Identifiers[0].URL, "cve.mitre.org")

		// Check CWE identifier
		assert.Equal(t, gitLabIdentifierTypeCWE, vuln.Identifiers[1].Type)
		assert.Equal(t, "CWE-79", vuln.Identifiers[1].Name)
		assert.Equal(t, "CWE-79", vuln.Identifiers[1].Value)
		assert.Contains(t, vuln.Identifiers[1].URL, "cwe.mitre.org")

		// Check GHSA identifier
		assert.Equal(t, gitLabIdentifierTypeGHSA, vuln.Identifiers[2].Type)
		assert.Equal(t, "GHSA-abcd-efgh-ijkl", vuln.Identifiers[2].Name)
		assert.Equal(t, "GHSA-abcd-efgh-ijkl", vuln.Identifiers[2].Value)
		assert.Contains(t, vuln.Identifiers[2].URL, "github.com/advisories")
	})

	t.Run("Time Format", func(t *testing.T) {
		testTime := time.Date(2024, 3, 15, 14, 30, 45, 0, time.UTC)
		formatted := gitlabFormatTime(testTime)
		assert.Equal(t, "2024-03-15T14:30:45", formatted)
	})

	t.Run("Maximum Identifiers", func(t *testing.T) {
		reporter, err := getGitLabReporter(reportPath)
		assert.NoError(t, err)

		// Create aliases with more than 20 identifiers
		// As per GitLab's limit
		aliases := make([]string, 25)
		for i := 0; i < 25; i++ {
			aliases[i] = fmt.Sprintf("CVE-2024-%d", i)
		}

		manifest := &models.PackageManifest{
			Path: "test/package.json",
			Packages: []*models.Package{
				{
					PackageDetails: models.NewPackageDetail("npm", "test-package", "1.0.0"),
					Insights: &insightapi.PackageVersionInsight{
						Vulnerabilities: &[]insightapi.PackageVulnerability{
							{
								Id:      utils.StringPtr("VULN-123"),
								Aliases: &aliases,
							},
						},
					},
				},
			},
		}

		reporter.AddManifest(manifest)
		err = reporter.Finish()
		assert.NoError(t, err)

		// Read and verify the report
		data, err := os.ReadFile(reportPath)
		assert.NoError(t, err)

		var report gitLabReport
		err = json.Unmarshal(data, &report)
		assert.NoError(t, err)

		// Verify maximum identifiers limit
		assert.Len(t, report.Vulnerabilities[0].Identifiers, 20)
	})

	t.Run("Report With Malicious Package", func(t *testing.T) {
		reporter, err := getGitLabReporter(reportPath)
		assert.NoError(t, err)

		manifest := &models.PackageManifest{
			Path: "test/package.json",
			Packages: []*models.Package{
				{
					PackageDetails: models.NewPackageDetail("npm", "malicious-package", "1.0.0"),
					Depth:          0,
					Insights:       &insightapi.PackageVersionInsight{}, // not make package skip
					MalwareAnalysis: &models.MalwareAnalysisResult{
						AnalysisId:   "123",
						IsMalware:    true,
						IsSuspicious: false,
						Report: &malysisv1.Report{
							ReportId: "report-123",
							Inference: &malysisv1.Report_Inference{
								Summary: "Package contains malicious code",
								Details: "Found suspicious eval usage and data exfiltration attempts",
							},
						},
					},
				},
			},
		}

		reporter.AddManifest(manifest)
		err = reporter.Finish()
		assert.NoError(t, err)

		// Read and verify the report
		data, err := os.ReadFile(reportPath)
		assert.NoError(t, err)

		// Debug: Print the report data
		fmt.Printf("Report data: %s\n", string(data))

		var report gitLabReport
		err = json.Unmarshal(data, &report)
		assert.NoError(t, err)

		// Debug: Print the vulnerabilities
		fmt.Printf("Vulnerabilities: %+v\n", report.Vulnerabilities)

		// Verify malicious package reporting
		assert.Len(t, report.Vulnerabilities, 1)
		vuln := report.Vulnerabilities[0]

		// Check basic vulnerability info
		assert.Equal(t, "MAL-123", vuln.ID)
		assert.Equal(t, "malicious-package@1.0.0 is malware/suspicious package", vuln.Name)
		assert.Equal(t, SeverityCritical, vuln.Severity)
		assert.Equal(t, "Package contains malicious code\n\nFound suspicious eval usage and data exfiltration attempts", vuln.Description)

		// Check location info
		assert.Equal(t, "test/package.json", vuln.Location.File)
		assert.Equal(t, "malicious-package", vuln.Location.Dependency.Package.Name)
		assert.Equal(t, "1.0.0", vuln.Location.Dependency.Version)
		assert.True(t, vuln.Location.Dependency.Direct)

		// Check identifiers
		assert.Len(t, vuln.Identifiers, 1)

		// Check malware identifier
		assert.Equal(t, gitLabIdentifierTypeMALWARE, vuln.Identifiers[0].Type)
		assert.Equal(t, "MAL-123", vuln.Identifiers[0].Name)
		assert.Equal(t, "MAL-123", vuln.Identifiers[0].Value)
		assert.Equal(t, malysis.ReportURL("report-123"), vuln.Identifiers[0].URL)
	})

	t.Run("Invalid Report Path", func(t *testing.T) {
		reporter, _ := NewGitLabReporter(GitLabReporterConfig{
			Path: "/nonexistent/directory/report.json",
		})
		err := reporter.Finish()
		assert.Error(t, err)
	})
}
