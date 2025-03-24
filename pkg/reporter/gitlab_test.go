package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/common/utils"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

func TestGitLabReporter(t *testing.T) {
	// Create a temporary directory for test reports
	tmpDir, err := os.MkdirTemp("", "gitlab-reporter-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	reportPath := filepath.Join(tmpDir, "gl-dependency-scanning-report.json")

	t.Run("NewGitLabReporter", func(t *testing.T) {
		reporter, err := NewGitLabReporter(GitLabReporterConfig{
			Path: reportPath,
		})
		assert.NoError(t, err)
		assert.NotNil(t, reporter)
		assert.Equal(t, "GitLab Dependency Scanning Report Generator", reporter.Name())
	})

	t.Run("Empty Report", func(t *testing.T) {
		reporter, _ := NewGitLabReporter(GitLabReporterConfig{
			Path: reportPath,
		})
		err := reporter.Finish()
		assert.NoError(t, err)

		// Read and verify the report
		data, err := os.ReadFile(reportPath)
		assert.NoError(t, err)

		var report GitLabReport
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
		reporter, _ := NewGitLabReporter(GitLabReporterConfig{
			Path: reportPath,
		})

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
		err := reporter.Finish()
		assert.NoError(t, err)

		// Read and verify the report
		data, err := os.ReadFile(reportPath)
		assert.NoError(t, err)

		var report GitLabReport
		err = json.Unmarshal(data, &report)
		assert.NoError(t, err)

		// Verify vulnerabilities
		assert.Len(t, report.Vulnerabilities, 1)
		vuln := report.Vulnerabilities[0]

		// Check basic vulnerability info
		assert.Equal(t, "VULN-123", vuln.ID)
		assert.Equal(t, "Test vulnerability", vuln.Name)
		assert.Equal(t, "High", vuln.Severity)

		// Check location info
		assert.Equal(t, "test/package.json", vuln.Location.File)
		assert.Equal(t, "test-package", vuln.Location.Dependency.Package.Name)
		assert.Equal(t, "1.0.0", vuln.Location.Dependency.Version)
		assert.True(t, vuln.Location.Dependency.Direct)

		// Check identifiers (should be in priority order: CVE, CWE, GHSA)
		assert.GreaterOrEqual(t, len(vuln.Identifiers), 3)

		// Check CVE identifier
		assert.Equal(t, "cve", vuln.Identifiers[0].Type)
		assert.Equal(t, "CVE-2023-1234", vuln.Identifiers[0].Name)
		assert.Equal(t, "CVE-2023-1234", vuln.Identifiers[0].Value)
		assert.Contains(t, vuln.Identifiers[0].URL, "cve.mitre.org")

		// Check CWE identifier
		assert.Equal(t, "cwe", vuln.Identifiers[1].Type)
		assert.Equal(t, "CWE-79", vuln.Identifiers[1].Name)
		assert.Equal(t, "79", vuln.Identifiers[1].Value)
		assert.Contains(t, vuln.Identifiers[1].URL, "cwe.mitre.org")

		// Check GHSA identifier
		assert.Equal(t, "ghsa", vuln.Identifiers[2].Type)
		assert.Equal(t, "GHSA-abcd-efgh-ijkl", vuln.Identifiers[2].Name)
		assert.Equal(t, "abcd-efgh-ijkl", vuln.Identifiers[2].Value)
		assert.Contains(t, vuln.Identifiers[2].URL, "github.com/advisories")
	})

	t.Run("Time Format", func(t *testing.T) {
		testTime := time.Date(2024, 3, 15, 14, 30, 45, 0, time.UTC)
		formatted := formatTime(testTime)
		assert.Equal(t, "2024-03-15T14:30:45", formatted)
	})

	t.Run("Maximum Identifiers", func(t *testing.T) {
		reporter, _ := NewGitLabReporter(GitLabReporterConfig{
			Path: reportPath,
		})

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
		err := reporter.Finish()
		assert.NoError(t, err)

		// Read and verify the report
		data, err := os.ReadFile(reportPath)
		assert.NoError(t, err)

		var report GitLabReport
		err = json.Unmarshal(data, &report)
		assert.NoError(t, err)

		// Verify maximum identifiers limit
		assert.Len(t, report.Vulnerabilities[0].Identifiers, 20)
	})

	t.Run("Invalid Report Path", func(t *testing.T) {
		reporter, _ := NewGitLabReporter(GitLabReporterConfig{
			Path: "/nonexistent/directory/report.json",
		})
		err := reporter.Finish()
		assert.Error(t, err)
	})
}
