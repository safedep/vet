package reporter

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/safedep/dry/semver"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
)

const (
	summaryListPrependText = "  ** "

	summaryWeightCriticalVuln = 5
	summaryWeightHighVuln     = 3
	summaryWeightMediumVuln   = 1
	summaryWeightLowVuln      = 0
	summaryWeightUnpopular    = 2
	summaryWeightMajorDrift   = 2

	summaryReportMaxUpgradeAdvice = 5
)

type summaryReporterRemediationData struct {
	pkg   *models.Package
	score int
}

type summaryReporter struct {
	summary struct {
		manifests int
		packages  int

		vulns struct {
			critical int
			high     int
			medium   int
			low      int
		}

		metrics struct {
			unpopular int
			drifts    int
		}
	}

	// Map of pkgId and associated meta for building remediation advice
	remediationScores map[string]*summaryReporterRemediationData
}

func NewSummaryReporter() (Reporter, error) {
	return &summaryReporter{
		remediationScores: make(map[string]*summaryReporterRemediationData),
	}, nil
}

func (r *summaryReporter) Name() string {
	return "Summary Report Generator"
}

func (r *summaryReporter) AddManifest(manifest *models.PackageManifest) {
	for _, pkg := range manifest.Packages {
		r.processForVulns(pkg)
		r.processForPopularity(pkg)
		r.processForVersionDrift(pkg)

		r.summary.packages += 1
	}

	r.summary.manifests += 1
}

func (r *summaryReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {}

func (r *summaryReporter) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *summaryReporter) processForVersionDrift(pkg *models.Package) {
	insight := utils.SafelyGetValue(pkg.Insights)

	version := pkg.PackageDetails.Version
	latestVersion := utils.SafelyGetValue(insight.PackageCurrentVersion)

	// Ignore for transitive dependencies
	if pkg.Depth > 0 {
		return
	}

	if utils.IsEmptyString(version) || utils.IsEmptyString(latestVersion) {
		return
	}

	driftType, _ := semver.Diff(version, latestVersion)
	if driftType.IsMajor() {
		r.summary.metrics.drifts += 1
		r.addPkgForRemediationAdvice(pkg, summaryWeightMajorDrift)
	}
}

func (r *summaryReporter) processForPopularity(pkg *models.Package) {
	insight := utils.SafelyGetValue(pkg.Insights)
	projects := utils.SafelyGetValue(insight.Projects)

	// Ignore transitive dependencies from popularity check
	if pkg.Depth > 0 {
		return
	}

	if len(projects) > 0 {
		p := projects[0]

		starsCount := utils.SafelyGetValue(p.Stars)
		projectType := utils.SafelyGetValue(p.Type)

		if (strings.EqualFold(projectType, "github")) && (starsCount < 10) {
			r.summary.metrics.unpopular += 1
			r.addPkgForRemediationAdvice(pkg, summaryWeightUnpopular)
		}
	}
}

func (r *summaryReporter) processForVulns(pkg *models.Package) {
	insight := utils.SafelyGetValue(pkg.Insights)
	for _, vuln := range utils.SafelyGetValue(insight.Vulnerabilities) {
		for _, s := range utils.SafelyGetValue(vuln.Severities) {
			sevType := utils.SafelyGetValue(s.Type)
			risk := utils.SafelyGetValue(s.Risk)

			if (sevType != insightapi.PackageVulnerabilitySeveritiesTypeCVSSV2) &&
				(sevType != insightapi.PackageVulnerabilitySeveritiesTypeCVSSV3) {
				continue
			}

			switch risk {
			case insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL:
				r.summary.vulns.critical += 1
				r.addPkgForRemediationAdvice(pkg, summaryWeightCriticalVuln)
				break
			case insightapi.PackageVulnerabilitySeveritiesRiskHIGH:
				r.summary.vulns.high += 1
				r.addPkgForRemediationAdvice(pkg, summaryWeightHighVuln)
				break
			case insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM:
				r.summary.vulns.medium += 1
				r.addPkgForRemediationAdvice(pkg, summaryWeightMediumVuln)
				break
			case insightapi.PackageVulnerabilitySeveritiesRiskLOW:
				r.summary.vulns.low += 1
				r.addPkgForRemediationAdvice(pkg, summaryWeightLowVuln)
				break
			}
		}
	}
}

func (r *summaryReporter) addPkgForRemediationAdvice(pkg *models.Package, weight int) {
	if _, ok := r.remediationScores[pkg.Id()]; !ok {
		r.remediationScores[pkg.Id()] = &summaryReporterRemediationData{
			pkg: pkg,
		}
	}

	r.remediationScores[pkg.Id()].score += weight
}

func (r *summaryReporter) Finish() error {
	fmt.Println(summaryListPrependText, text.BgBlue.Sprint(" Summary of Findings "))
	fmt.Println()
	fmt.Println(text.FgHiRed.Sprint(summaryListPrependText, r.vulnSummaryStatement()))
	fmt.Println()
	fmt.Println(text.FgHiYellow.Sprint(summaryListPrependText, r.popularityCountStatement()))
	fmt.Println()
	fmt.Println(text.FgHiYellow.Sprint(summaryListPrependText, r.majorVersionDriftStatement()))
	fmt.Println()
	fmt.Println(text.Faint.Sprint(summaryListPrependText, r.manifestCountStatement()))
	fmt.Println()
	r.renderRemediationAdvice()
	fmt.Println()
	fmt.Println("Install as a security gate in CI for incremental scan and blocking risky dependencies")
	fmt.Println("Run `vet ci` to generate CI scripts")
	fmt.Println()
	fmt.Println("Run with `vet --filter=\"...\"` for custom filters to identify risky libraries")
	fmt.Println()
	fmt.Println("For more details", text.Bold.Sprint("https://github.com/safedep/vet"))

	return nil
}

func (r *summaryReporter) renderRemediationAdvice() {
	sortedPackages := []*summaryReporterRemediationData{}
	for _, value := range r.remediationScores {
		i := sort.Search(len(sortedPackages), func(i int) bool {
			return value.score >= sortedPackages[i].score
		})

		if i == len(sortedPackages) {
			sortedPackages = append(sortedPackages, value)
		}

		sortedPackages = append(sortedPackages[:i+1], sortedPackages[i:]...)
		sortedPackages[i] = value
	}

	fmt.Println(text.Bold.Sprint("Consider upgrading the following libraries for maximum impact:"))
	fmt.Println()

	tbl := table.NewWriter()
	tbl.SetOutputMirror(os.Stdout)
	tbl.SetStyle(table.StyleLight)

	tbl.AppendHeader(table.Row{"Package", "Update To", "Risk Score"})
	for idx, sp := range sortedPackages {
		if idx >= summaryReportMaxUpgradeAdvice {
			continue
		}

		insight := utils.SafelyGetValue(sp.pkg.Insights)

		tbl.AppendRow(table.Row{
			r.packageNameForRemediationAdvice(sp.pkg),
			utils.SafelyGetValue(insight.PackageCurrentVersion),
			sp.score,
		})
	}

	tbl.Render()

	if len(sortedPackages) > summaryReportMaxUpgradeAdvice {
		fmt.Println()
		fmt.Println(text.FgHiYellow.Sprint(
			fmt.Sprintf("There are %d more libraries that should be upgraded to reduce risk",
				len(sortedPackages)-summaryReportMaxUpgradeAdvice),
		))

		fmt.Println(text.Bold.Sprint("Run vet with `--report-markdown=/path/to/report.md` for details"))
	}
}

func (r *summaryReporter) packageNameForRemediationAdvice(pkg *models.Package) string {
	return fmt.Sprintf("%s@%s", pkg.PackageDetails.Name,
		pkg.PackageDetails.Version)
}

func (r *summaryReporter) vulnSummaryStatement() string {
	return fmt.Sprintf("%d critical, %d high and %d other vulnerabilities were identifier",
		r.summary.vulns.critical, r.summary.vulns.high,
		r.summary.vulns.medium+r.summary.vulns.low)
}

func (r *summaryReporter) manifestCountStatement() string {
	return fmt.Sprintf("across %d libraries in %d manifest(s)",
		r.summary.packages,
		r.summary.manifests)
}

func (r *summaryReporter) popularityCountStatement() string {
	return fmt.Sprintf("%d potentially unpopular library identified as direct dependency",
		r.summary.metrics.unpopular)
}

func (r *summaryReporter) majorVersionDriftStatement() string {
	return fmt.Sprintf("%d libraries are out of date with major version drift in direct dependencies",
		r.summary.metrics.drifts)
}
