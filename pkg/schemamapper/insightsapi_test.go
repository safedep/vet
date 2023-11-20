package schemamapper

import (
	"testing"

	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/gen/models"
	"github.com/stretchr/testify/assert"
)

func TestInsightsVulnerabilitySeverityToModelSeverity(t *testing.T) {
	cases := []struct {
		name string

		actualType  insightapi.PackageVulnerabilitySeveritiesType
		actualRisk  insightapi.PackageVulnerabilitySeveritiesRisk
		actualScore string

		expectedType  models.InsightVulnerabilitySeverityType
		expectedRisk  models.InsightVulnerabilitySeverityRisk
		expectedScore string
	}{
		{
			"Positive Case",

			insightapi.PackageVulnerabilitySeveritiesTypeCVSSV2,
			insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL,
			"Score-A",

			models.InsightVulnerabilitySeverityType_InsightVulnerabilitySeverity_CVSSV2,
			models.InsightVulnerabilitySeverityRisk_VULN_RISK_CRITICAL,
			"Score-A",
		},
		{
			"When valid type is not available",

			insightapi.PackageVulnerabilitySeveritiesType("BAD-TYPE"),
			insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL,
			"Score-B",

			models.InsightVulnerabilitySeverityType_InsightVulnerabilitySeverity_UNKNOWN,
			models.InsightVulnerabilitySeverityRisk_VULN_RISK_CRITICAL,
			"Score-B",
		},
		{
			"When valid risk is not available",

			insightapi.PackageVulnerabilitySeveritiesTypeCVSSV2,
			insightapi.PackageVulnerabilitySeveritiesRisk("WHAT?"),
			"Score-C",

			models.InsightVulnerabilitySeverityType_InsightVulnerabilitySeverity_CVSSV2,
			models.InsightVulnerabilitySeverityRisk_VULN_RISK_UNKNOWN,
			"Score-C",
		},
		{
			"Score can be empty",

			insightapi.PackageVulnerabilitySeveritiesTypeCVSSV2,
			insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL,
			"",

			models.InsightVulnerabilitySeverityType_InsightVulnerabilitySeverity_CVSSV2,
			models.InsightVulnerabilitySeverityRisk_VULN_RISK_CRITICAL,
			"",
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			src := InsightsVulnerabilitySeverity{
				Type:  &test.actualType,
				Risk:  &test.actualRisk,
				Score: &test.actualScore,
			}

			sev, err := InsightsVulnerabilitySeverityToModelSeverity(&src)
			assert.Nil(t, err)

			assert.Equal(t, test.expectedScore, sev.Score)
			assert.Equal(t, test.expectedRisk, sev.Risk)
			assert.Equal(t, test.expectedType, sev.Type)
		})
	}
}
