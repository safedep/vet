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

type internalErrorCounter struct {
	malwareAnalysisQuotaLimitErrorCount         int
	malwareAnalysisEntitlementAutoSwitchEnabled bool
}

func renderQuotaLimitErrorMessages(quotaExceededErrCnt int) string {
	return fmt.Sprintf("You have reached your quota for on-demand malicious package "+
		"scanning. %d on-demand analysis requests were denied. Please see safedep.io/pricing for "+
		"upgrade.", quotaExceededErrCnt)
}

func renderMarkdownQuotaLimitErrorMessages(quotaExceededErrCnt int) string {
	return fmt.Sprintf("⚠️ You have reached your **quota** for on-demand malicious package "+
		"scanning. `%d` on-demand analysis requests were **denied**. Please see [safedep.io/pricing](https://safedep.io/pricing) for "+
		"upgrade.", quotaExceededErrCnt)
}

func renderMarkdownEntitlementAutoSwitchEnabled() string {
	return fmt.Sprintln("🔀 **On-demand** malicious package scanning is not available on the **Free plan**. " +
		"Your scan was configured to use known malicious packages feed. **[Upgrade](https://safedep.io/pricing)** to enable on-demand scanning.")
}
