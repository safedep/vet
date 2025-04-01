package reporter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	malysisv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/malysis/v1"
	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/safedep/vet/gen/checks"
	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/utils"
	"github.com/safedep/vet/pkg/malysis"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func getGitLabReporter(reportPath string) (*gitLabReporter, error) {
	return NewGitLabReporter(GitLabReporterConfig{
		Path: reportPath,
		Tool: ToolMetadata{
			Name:           "vet",
			Version:        "latest",
			InformationURI: "https://github.com/safedep/vet",
			VendorName:     "safedep",
		},
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
								Id: utils.PtrTo("VULN-123"),
								Aliases: &[]string{
									"CVE-2023-1234",
									"CWE-79",
									"GHSA-abcd-efgh-ijkl",
								},
								Summary: utils.PtrTo("Test vulnerability"),
								Severities: &[]struct {
									Risk  *insightapi.PackageVulnerabilitySeveritiesRisk `json:"risk,omitempty"`
									Score *string                                        `json:"score,omitempty"`
									Type  *insightapi.PackageVulnerabilitySeveritiesType `json:"type,omitempty"`
								}{
									{
										Risk: (*insightapi.PackageVulnerabilitySeveritiesRisk)(utils.PtrTo("HIGH")),
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
		reporter, err := getGitLabReporter(reportPath)
		assert.NoError(t, err)

		testTime := time.Date(2024, 3, 15, 14, 30, 45, 0, time.UTC)
		formatted := reporter.gitlabFormatTime(testTime)
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
								Id:      utils.PtrTo("VULN-123"),
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

func TestGitLabReporterPolicyViolations(t *testing.T) {
	// Create a temporary file for the report
	tmpFile, err := os.CreateTemp("", "gitlab-report-*.json")
	require.NoError(t, err)
	defer os.Remove(tmpFile.Name())

	// Create reporter
	reporter, err := NewGitLabReporter(GitLabReporterConfig{
		Path: tmpFile.Name(),
		Tool: ToolMetadata{
			Name:       "test-tool",
			Version:    "1.0.0",
			VendorName: "test-vendor",
		},
	})
	require.NoError(t, err)

	// Create test manifest and package
	manifest := &models.PackageManifest{
		Path:      "test/path/package.json",
		Ecosystem: string(lockfile.NpmEcosystem),
	}

	pkg := &models.Package{
		PackageDetails: lockfile.PackageDetails{
			Name:      "test-pkg",
			Version:   "1.0.0",
			Ecosystem: lockfile.NpmEcosystem,
		},
		Manifest: manifest,
		Insights: &insightapi.PackageVersionInsight{
			PackageCurrentVersion: utils.StringPtr("2.0.0"),
		},
	}

	// Create test policy violation event
	event := &analyzer.AnalyzerEvent{
		Type:     analyzer.ET_FilterExpressionMatched,
		Package:  pkg,
		Manifest: manifest,
		Filter: &filtersuite.Filter{
			Name:      "test-policy",
			Value:     "test-value",
			Summary:   "Test policy violation",
			CheckType: checks.CheckType_CheckTypeVulnerability,
		},
	}

	// Add event to reporter
	reporter.AddAnalyzerEvent(event)

	// Finish report generation
	err = reporter.Finish()
	require.NoError(t, err)

	// Read and parse the generated report
	reportData, err := os.ReadFile(tmpFile.Name())
	require.NoError(t, err)

	var report gitLabReport
	err = json.Unmarshal(reportData, &report)
	require.NoError(t, err)

	// Verify the policy violation details
	require.Len(t, report.Vulnerabilities, 1)
	vuln := report.Vulnerabilities[0]

	// Check basic fields
	assert.Contains(t, vuln.ID, fmt.Sprintf("%s-%s", gitlabCustomPolicySuffix, event.Package.Id()))
	assert.Equal(t, gitlabPolicyViolationSeverity, vuln.Severity)
	assert.Equal(t, "Upgrade to latest version **`2.0.0`**", vuln.Solution)

	// Check location details
	assert.Equal(t, "test/path/package.json", vuln.Location.File)
	assert.Equal(t, "test-pkg", vuln.Location.Dependency.Package.Name)
	assert.Equal(t, "1.0.0", vuln.Location.Dependency.Version)

	// Check identifiers
	require.Len(t, vuln.Identifiers, 1)
}
