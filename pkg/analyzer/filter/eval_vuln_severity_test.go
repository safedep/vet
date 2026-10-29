package filter

import (
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/models"
)

type testVulnSeverity = struct {
	Risk  *insightapi.PackageVulnerabilitySeveritiesRisk `json:"risk,omitempty"`
	Score *string                                        `json:"score,omitempty"`
	Type  *insightapi.PackageVulnerabilitySeveritiesType `json:"type,omitempty"`
}

func testSeverity(t insightapi.PackageVulnerabilitySeveritiesType,
	r insightapi.PackageVulnerabilitySeveritiesRisk,
) testVulnSeverity {
	return testVulnSeverity{Type: utils.PtrTo(t), Risk: utils.PtrTo(r)}
}

func TestEvaluatorVulnerabilityBucketsPreferTheMostCurrentCVSS(t *testing.T) {
	const (
		v2 = insightapi.PackageVulnerabilitySeveritiesTypeCVSSV2
		v3 = insightapi.PackageVulnerabilitySeveritiesTypeCVSSV3
		v4 = models.VulnerabilitySeverityTypeCVSSV4

		critical = insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL
		high     = insightapi.PackageVulnerabilitySeveritiesRiskHIGH
		medium   = insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM
		low      = insightapi.PackageVulnerabilitySeveritiesRiskLOW
	)

	cases := []struct {
		name       string
		severities []testVulnSeverity
		filter     string
		expected   bool
	}{
		{
			name:       "critical CVSS v4 only",
			severities: []testVulnSeverity{testSeverity(v4, critical)},
			filter:     "vulns.critical.size() > 0",
			expected:   true,
		},
		{
			name:       "high CVSS v4 only",
			severities: []testVulnSeverity{testSeverity(v4, high)},
			filter:     "vulns.high.size() > 0",
			expected:   true,
		},
		{
			name:       "v4 high wins over v3 medium: in the high bucket",
			severities: []testVulnSeverity{testSeverity(v3, medium), testSeverity(v4, high)},
			filter:     "vulns.high.size() > 0",
			expected:   true,
		},
		{
			name:       "v4 high wins over v3 medium: not in the medium bucket",
			severities: []testVulnSeverity{testSeverity(v3, medium), testSeverity(v4, high)},
			filter:     "vulns.medium.size() > 0",
			expected:   false,
		},
		{
			name:       "v4 wins whatever the order",
			severities: []testVulnSeverity{testSeverity(v4, high), testSeverity(v3, medium)},
			filter:     "vulns.high.size() > 0",
			expected:   true,
		},
		{
			name:       "v3 wins over v2",
			severities: []testVulnSeverity{testSeverity(v2, high), testSeverity(v3, low)},
			filter:     "vulns.low.size() > 0",
			expected:   true,
		},
		{
			name:       "v3 only is unchanged",
			severities: []testVulnSeverity{testSeverity(v3, critical)},
			filter:     "vulns.critical.size() > 0",
			expected:   true,
		},
		{
			name:       "v2 only is unchanged",
			severities: []testVulnSeverity{testSeverity(v2, medium)},
			filter:     "vulns.medium.size() > 0",
			expected:   true,
		},
		{
			name: "an unspecified type is not bucketed",
			severities: []testVulnSeverity{
				testSeverity(insightapi.PackageVulnerabilitySeveritiesTypeUNSPECIFIED, critical),
			},
			filter:   "vulns.critical.size() > 0",
			expected: false,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := NewEvaluator("test", WithIgnoreError(false))
			assert.NoError(t, err)

			err = f.AddFilter(&filtersuite.Filter{Name: "test", Value: c.filter})
			assert.NoError(t, err)

			severities := c.severities
			pkg := &models.Package{
				Insights: &insightapi.PackageVersionInsight{
					Vulnerabilities: &[]insightapi.PackageVulnerability{
						{
							Id:         utils.PtrTo("GHSA-test"),
							Severities: &severities,
						},
					},
				},
			}

			result, err := f.EvalPackage(pkg)
			assert.NoError(t, err)
			assert.Equal(t, c.expected, result.Matched())
		})
	}
}
