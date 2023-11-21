package schemamapper

import (
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/gen/models"
)

// Unpacked vulnerability severity declaration as per
// Insights API for conversion to modelspec
type InsightsVulnerabilitySeverity struct {
	Risk  *insightapi.PackageVulnerabilitySeveritiesRisk `json:"risk,omitempty"`
	Score *string                                        `json:"score,omitempty"`
	Type  *insightapi.PackageVulnerabilitySeveritiesType `json:"type,omitempty"`
}

func InsightsVulnerabilitySeverityToModelSeverity(sev *InsightsVulnerabilitySeverity) (*models.InsightVulnerabilitySeverity, error) {
	severity := models.InsightVulnerabilitySeverity{}

	sevType := utils.SafelyGetValue(sev.Type)
	switch sevType {
	case insightapi.PackageVulnerabilitySeveritiesTypeCVSSV2:
		severity.Type = models.InsightVulnerabilitySeverity_CVSSV2
	case insightapi.PackageVulnerabilitySeveritiesTypeCVSSV3:
		severity.Type = models.InsightVulnerabilitySeverity_CVSSV3
	default:
		severity.Type = models.InsightVulnerabilitySeverity_UNKNOWN_TYPE
	}

	risk := utils.SafelyGetValue(sev.Risk)
	switch risk {
	case insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL:
		severity.Risk = models.InsightVulnerabilitySeverity_CRITICAL
	case insightapi.PackageVulnerabilitySeveritiesRiskHIGH:
		severity.Risk = models.InsightVulnerabilitySeverity_HIGH
	case insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM:
		severity.Risk = models.InsightVulnerabilitySeverity_MEDIUM
	case insightapi.PackageVulnerabilitySeveritiesRiskLOW:
		severity.Risk = models.InsightVulnerabilitySeverity_LOW
	}

	severity.Score = utils.SafelyGetValue(sev.Score)
	return &severity, nil
}
