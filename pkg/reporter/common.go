package reporter

import (
	"fmt"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/checks"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
)

type ToolMetadata struct {
	Name                 string
	Version              string
	Purl                 string
	InformationURI       string
	VendorName           string
	VendorInformationURI string
}

func getPolicyViolationSolution(event *analyzer.AnalyzerEvent) string {
	switch event.Filter.GetCheckType() {
	case checks.CheckType_CheckTypeVulnerability:
		return getVulnerabilitySolution(event.Package)

	case checks.CheckType_CheckTypePopularity:
		return "Consider using a more popular alternative package"

	case checks.CheckType_CheckTypeLicense:
		return "Review and update package to comply with license policy"

	case checks.CheckType_CheckTypeMaintenance:
		return "Update package to align with maintenance policy"

	case checks.CheckType_CheckTypeSecurityScorecard:
		return "Review and improve package security posture"

	case checks.CheckType_CheckTypeMalware:
		return "Remove this package and review any affected code"

	case checks.CheckType_CheckTypeOther:
		return "Review and fix policy violation"

	default:
		return "Review and fix policy violation"
	}
}

func getVulnerabilitySolution(pkg *models.Package) string {
	solution := "No solution available for this vulnerability"

	if pkg.Insights != nil && pkg.Insights.PackageCurrentVersion != nil {
		latestVersion := utils.SafelyGetValue(pkg.Insights.PackageCurrentVersion)
		solution = fmt.Sprintf("Upgrade to latest version **`%s`**", latestVersion)
	}

	return solution
}
