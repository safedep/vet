package reporter

import (
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

func TestManifestRelativePath(t *testing.T) {
	testCases := []struct {
		name string

		currentWorkingDir string
		manifestFullPath  string

		expectError          bool
		expectedRelativePath string
	}{
		{
			name:              "valid current working directory",
			currentWorkingDir: "/home/user/work/company/project/source",
			manifestFullPath:  "/home/user/work/company/project/source/package-lock.json",

			expectError:          false,
			expectedRelativePath: "package-lock.json",
		},
		{
			name:              "valid current working directory with sub dir manifest path",
			currentWorkingDir: "/home/user/work/company/project/source",
			manifestFullPath:  "/home/user/work/company/project/source/apps/cli/go.mod",

			expectError:          false,
			expectedRelativePath: "apps/cli/go.mod",
		},
		{
			name:              "empty current working directory - error on os.Getwd()",
			currentWorkingDir: "", // os.Getwd() failed, then currentWorkingDir = ""
			manifestFullPath:  "/home/user/work/company/project/source/package-lock.json",
			expectError:       true,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			r := &summaryReporter{}
			relativePath, err := r.packageManifestRelativePath(test.currentWorkingDir, test.manifestFullPath)

			if test.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, relativePath, test.expectedRelativePath)
			}
		})
	}
}

func TestRenderInternalErrorMessages(t *testing.T) {
	t.Run("when quota exceeded error count is greater than 0", func(t *testing.T) {
		t.Parallel()

		r := &summaryReporter{}
		r.internalReportConfig.malwareAnalysisQuotaLimitErrorCount = 5

		expectedErrorMessage := "You have reached your quota for malicious package scanning.\n5 malicious package lookups were denied. Please see safedep.io/pricing for upgrade."

		actualErrorMessage := renderQuotaLimitErrorMessages(5)

		assert.Equal(t, expectedErrorMessage, actualErrorMessage)
	})
}

func TestSummaryReporterCountsEachVulnerabilityOnceByItsMostCurrentCVSS(t *testing.T) {
	const (
		v2 = insightapi.PackageVulnerabilitySeveritiesTypeCVSSV2
		v3 = insightapi.PackageVulnerabilitySeveritiesTypeCVSSV3
		v4 = models.VulnerabilitySeverityTypeCVSSV4
	)

	type severity = struct {
		Risk  *insightapi.PackageVulnerabilitySeveritiesRisk `json:"risk,omitempty"`
		Score *string                                        `json:"score,omitempty"`
		Type  *insightapi.PackageVulnerabilitySeveritiesType `json:"type,omitempty"`
	}

	sev := func(t insightapi.PackageVulnerabilitySeveritiesType,
		r insightapi.PackageVulnerabilitySeveritiesRisk,
	) severity {
		return severity{Type: utils.PtrTo(t), Risk: utils.PtrTo(r)}
	}

	critical := insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL
	high := insightapi.PackageVulnerabilitySeveritiesRiskHIGH
	medium := insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM

	vulns := []insightapi.PackageVulnerability{
		// rated only by CVSS v4
		{Id: utils.PtrTo("GHSA-v4-only"), Severities: &[]severity{sev(v4, critical)}},
		// v4 is higher than v3: counted once, as high
		{Id: utils.PtrTo("GHSA-v4-v3"), Severities: &[]severity{sev(v3, medium), sev(v4, high)}},
		// v2 and v3 together used to be counted twice
		{Id: utils.PtrTo("GHSA-v3-v2"), Severities: &[]severity{sev(v2, high), sev(v3, medium)}},
		// no rating that we can bucket on
		{Id: utils.PtrTo("GHSA-unspecified"), Severities: &[]severity{
			sev(insightapi.PackageVulnerabilitySeveritiesTypeUNSPECIFIED, critical),
		}},
	}

	r := &summaryReporter{
		remediationScores: make(map[string]*summaryReporterRemediationData),
		vulnerabilityInfo: make(map[string]*summaryReporterVulnerabilityData),
	}
	r.processForVulns(&models.Package{
		PackageDetails: models.NewPackageDetail(models.EcosystemNpm, "tinypool", "1.1.1"),
		Insights:       &insightapi.PackageVersionInsight{Vulnerabilities: &vulns},
	})

	assert.Equal(t, 1, r.summary.vulns.critical)
	assert.Equal(t, 1, r.summary.vulns.high)
	assert.Equal(t, 1, r.summary.vulns.medium)
	assert.Equal(t, 0, r.summary.vulns.low)
}
