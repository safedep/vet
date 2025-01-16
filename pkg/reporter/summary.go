package reporter

import (
	"cmp"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/safedep/dry/semver"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/exceptions"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/readers"
)

const (
	summaryListPrependText = "  ** "

	// Opinionated weights for scoring
	summaryWeightCriticalVuln = 10
	summaryWeightHighVuln     = 8
	summaryWeightMediumVuln   = 2
	summaryWeightLowVuln      = 1
	summaryWeightUnpopular    = 1
	summaryWeightMajorDrift   = 2

	// Opinionated thresholds for identifying repo popularity by stars
	minStarsForPopularity = 10

	tagVuln      = "vulnerability"
	tagUnpopular = "low popularity"
	tagDrift     = "drift"

	summaryReportMaxUpgradeAdvice = 5
)

type summaryReporterInputViolationData struct {
	Ecosystem string
	PkgName   string
	Message   string
}

type summaryReporterRemediationData struct {
	pkg   *models.Package
	score int
	tags  []string

	// Used in group by primitive, where remediating the pkg
	// leads to remediating all the packages in the array
	remediates []*summaryReporterRemediationData
}

type summaryReporterVulnerabilityData struct {
	pkg             *models.Package
	vulnerabilities map[insightapi.PackageVulnerabilitySeveritiesRisk][]string
}

type SummaryReporterConfig struct {
	MaxAdvice               int
	GroupByDirectDependency bool
}

type summaryReporter struct {
	config SummaryReporterConfig

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

		provenance struct {
			none       int
			verified   int
			unverified int
		}

		// Stats for active malware scanning results ONLY
		// Do not use these stats for OSV based malware database results
		malware struct {
			scanned    int
			malicious  int
			suspicious int
		}
	}

	// Map of pkgId and associated meta for building remediation advice
	remediationScores map[string]*summaryReporterRemediationData

	// Map of pkgId and associated meta for rendering vulnerability risk
	vulnerabilityInfo map[string]*summaryReporterVulnerabilityData

	// Map of pkgId and violation information
	violations map[string]*summaryReporterInputViolationData

	// List of lockfile poisoning detection signals
	lockfilePoisoning []string
}

func NewSummaryReporter(config SummaryReporterConfig) (Reporter, error) {
	if config.MaxAdvice == 0 {
		config.MaxAdvice = summaryReportMaxUpgradeAdvice
	}

	return &summaryReporter{
		config:            config,
		remediationScores: make(map[string]*summaryReporterRemediationData),
		vulnerabilityInfo: make(map[string]*summaryReporterVulnerabilityData),
		violations:        make(map[string]*summaryReporterInputViolationData),
	}, nil
}

func (r *summaryReporter) Name() string {
	return "Summary Report Generator"
}

func (r *summaryReporter) AddManifest(manifest *models.PackageManifest) {
	readers.NewManifestModelReader(manifest).EnumPackages(func(pkg *models.Package) error {
		r.processForVulns(pkg)
		r.processForMalware(pkg)
		r.processForPopularity(pkg)
		r.processForVersionDrift(pkg)
		r.processForProvenance(pkg)

		r.summary.packages += 1
		return nil
	})

	r.summary.manifests += 1
}

func (r *summaryReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	if event.IsLockfilePoisoningSignal() {
		r.lockfilePoisoning = append(r.lockfilePoisoning, event.Message.(string))
	}

	if !event.IsFilterMatch() {
		return
	}

	if event.Package == nil {
		return
	}

	if event.Package.Manifest == nil {
		return
	}

	pkgId := event.Package.Id()
	if _, ok := r.violations[pkgId]; ok {
		return
	}

	if msg, ok := event.Message.(string); !ok {
		return
	} else {
		v := summaryReporterInputViolationData{
			Ecosystem: string(event.Package.Ecosystem),
			PkgName:   fmt.Sprintf("%s@%s", event.Package.Name, event.Package.Version),
			Message:   msg,
		}
		r.violations[pkgId] = &v
	}

}

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
		r.addPkgForRemediationAdvice(pkg, summaryWeightMajorDrift, tagDrift)
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

		if (strings.EqualFold(projectType, "github")) && (starsCount < minStarsForPopularity) {
			r.summary.metrics.unpopular += 1
			r.addPkgForRemediationAdvice(pkg, summaryWeightUnpopular, tagUnpopular)
		}
	}
}

func (r *summaryReporter) processForMalware(pkg *models.Package) {
	// First we check for known malware from OSV MAL database
	insight := utils.SafelyGetValue(pkg.Insights)
	vulns := utils.SafelyGetValue(insight.Vulnerabilities)

	malwareTaggerFn := func(pkg *models.Package) {
		r.summary.vulns.critical += 1
		r.addPkgForRemediationAdvice(pkg, summaryWeightCriticalVuln, "malware")
	}

	suspiciousTaggerFn := func(pkg *models.Package) {
		r.summary.vulns.high += 1
		r.addPkgForRemediationAdvice(pkg, summaryWeightHighVuln, "suspicious")
	}

	for _, vuln := range vulns {
		// OSV API follows the convention of using MAL-YYYY-ID convention
		// as generated by https://github.com/ossf/malicious-packages
		if strings.HasPrefix(utils.SafelyGetValue(vuln.Id), "MAL-") {
			malwareTaggerFn(pkg)
		}
	}

	// Then we check for malware from Malysis package analysis service
	if ma := pkg.GetMalwareAnalysisResult(); ma != nil {
		r.summary.malware.scanned += 1
		if ma.IsMalware {
			r.summary.malware.malicious += 1
			malwareTaggerFn(pkg)
		} else if ma.IsSuspicious {
			r.summary.malware.suspicious += 1
			suspiciousTaggerFn(pkg)
		}
	}
}

func (r *summaryReporter) processForProvenance(pkg *models.Package) {
	if len(pkg.GetProvenances()) == 0 {
		r.summary.provenance.none += 1
		return
	}

	verified := false
	for _, p := range pkg.GetProvenances() {
		if p.Verified {
			verified = true
			break
		}
	}

	if verified {
		r.summary.provenance.verified += 1
	} else {
		r.summary.provenance.unverified += 1
	}
}

func (r *summaryReporter) processForVulns(pkg *models.Package) {
	insight := utils.SafelyGetValue(pkg.Insights)
	vulns := utils.SafelyGetValue(insight.Vulnerabilities)

	for _, vuln := range vulns {
		for _, s := range utils.SafelyGetValue(vuln.Severities) {
			sevType := utils.SafelyGetValue(s.Type)
			risk := utils.SafelyGetValue(s.Risk)

			if (sevType != insightapi.PackageVulnerabilitySeveritiesTypeCVSSV2) &&
				(sevType != insightapi.PackageVulnerabilitySeveritiesTypeCVSSV3) {
				continue
			}

			r.addPkgForVulnerabilityRisk(pkg, risk, utils.SafelyGetValue(vuln.Id))

			switch risk {
			case insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL:
				r.summary.vulns.critical += 1
				r.addPkgForRemediationAdvice(pkg, summaryWeightCriticalVuln, tagVuln)
				break
			case insightapi.PackageVulnerabilitySeveritiesRiskHIGH:
				r.summary.vulns.high += 1
				r.addPkgForRemediationAdvice(pkg, summaryWeightHighVuln, tagVuln)
				break
			case insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM:
				r.summary.vulns.medium += 1
				r.addPkgForRemediationAdvice(pkg, summaryWeightMediumVuln, tagVuln)
				break
			case insightapi.PackageVulnerabilitySeveritiesRiskLOW:
				r.summary.vulns.low += 1
				r.addPkgForRemediationAdvice(pkg, summaryWeightLowVuln, tagVuln)
				break
			}
		}
	}
}

func (r *summaryReporter) addPkgForRemediationAdvice(pkg *models.Package,
	weight int, tag string) {
	if _, ok := r.remediationScores[pkg.Id()]; !ok {
		r.remediationScores[pkg.Id()] = &summaryReporterRemediationData{
			pkg:  pkg,
			tags: []string{},
		}
	}

	r.remediationScores[pkg.Id()].score += weight

	if utils.FindInSlice(r.remediationScores[pkg.Id()].tags, tag) == -1 {
		r.remediationScores[pkg.Id()].tags = append(r.remediationScores[pkg.Id()].tags, tag)
	}
}

func (r *summaryReporter) addPkgForVulnerabilityRisk(pkg *models.Package,
	risk insightapi.PackageVulnerabilitySeveritiesRisk, vuln string) {
	if _, ok := r.vulnerabilityInfo[pkg.Id()]; !ok {
		r.vulnerabilityInfo[pkg.Id()] = &summaryReporterVulnerabilityData{
			pkg:             pkg,
			vulnerabilities: make(map[insightapi.PackageVulnerabilitySeveritiesRisk][]string),
		}
	}

	if _, ok := r.vulnerabilityInfo[pkg.Id()].vulnerabilities[risk]; !ok {
		r.vulnerabilityInfo[pkg.Id()].vulnerabilities[risk] = []string{}
	}

	r.vulnerabilityInfo[pkg.Id()].vulnerabilities[risk] =
		append(r.vulnerabilityInfo[pkg.Id()].vulnerabilities[risk], vuln)
}

func (r *summaryReporter) Finish() error {
	fmt.Println(summaryListPrependText, text.BgBlue.Sprint(" Summary of Findings "))
	fmt.Println()
	fmt.Println(text.FgHiRed.Sprint(summaryListPrependText, r.vulnSummaryStatement()))
	fmt.Println()
	fmt.Println(text.FgHiYellow.Sprint(summaryListPrependText, r.popularityCountStatement()))
	fmt.Println()
	fmt.Println(text.FgHiYellow.Sprint(summaryListPrependText, r.provenanceStatement()))
	fmt.Println()
	fmt.Println(text.FgHiYellow.Sprint(summaryListPrependText, r.malwareAnalysisStatement()))
	fmt.Println()
	fmt.Println(text.FgHiYellow.Sprint(summaryListPrependText, r.majorVersionDriftStatement()))
	fmt.Println()
	fmt.Println(text.Faint.Sprint(summaryListPrependText, r.manifestCountStatement()))
	fmt.Println()

	r.renderRemediationAdvice()
	fmt.Println()

	if exceptions.ActiveCount() > 0 {
		fmt.Println(text.Faint.Sprint(summaryListPrependText, r.exceptionsCountStatement()))
		fmt.Println()
	}

	if len(r.lockfilePoisoning) > 0 {
		fmt.Println(summaryListPrependText, text.Bold.Sprint(" Lockfile Poisoning Detected "))
		fmt.Println()

		for _, msg := range r.lockfilePoisoning {
			fmt.Println(text.WrapHard(text.BgRed.Sprint(summaryListPrependText, msg), 120))
		}

		fmt.Println()
	}

	fmt.Println("Run with `vet --filter=\"...\"` for custom filters to identify risky libraries")
	fmt.Println("For more details", text.Bold.Sprint("https://github.com/safedep/vet"))
	fmt.Println()

	return nil
}

func (r *summaryReporter) sortedRemediations() []*summaryReporterRemediationData {
	sortedPackages := []*summaryReporterRemediationData{}
	for _, value := range r.remediationScores {
		sortedPackages = append(sortedPackages, value)
	}

	slices.SortFunc(sortedPackages, func(a, b *summaryReporterRemediationData) int {
		if a.score == b.score {
			return cmp.Compare(a.pkg.GetName(), b.pkg.GetName())
		}

		// We want to sort by descending order
		return cmp.Compare(b.score, a.score)
	})

	return sortedPackages
}

// To be able to group by direct dependencies, we need to:
// - Enumerate through all package risks
// - Group by direct dependency if available
// - Track the packages that are remediated by the direct dependency
func (r *summaryReporter) sortedRemediationsGroupByDirectDependency() []*summaryReporterRemediationData {
	groupedRemediationPackages := map[string]*summaryReporterRemediationData{}
	for _, value := range r.remediationScores {
		// Get the package and dependency graph
		pkg := value.pkg
		dg := pkg.GetDependencyGraph()

		// If dependency graph is available
		if dg != nil {
			// Find the top level dependency that may result in upgrading affected package
			remediationPath := dg.PathToRoot(pkg)

			if len(remediationPath) > 1 {
				// Package has atleast 1 parent so we will group by the root pkg
				pkg = remediationPath[len(remediationPath)-1]
			}
		}

		if _, ok := groupedRemediationPackages[pkg.Id()]; !ok {
			groupedRemediationPackages[pkg.Id()] = &summaryReporterRemediationData{
				pkg:        pkg,
				score:      0,
				tags:       make([]string, 0),
				remediates: []*summaryReporterRemediationData{},
			}
		}

		groupedRemediationPackages[pkg.Id()].score = groupedRemediationPackages[pkg.Id()].score + value.score

		// TODO: Merge without duplicates
		groupedRemediationPackages[pkg.Id()].tags = append(groupedRemediationPackages[pkg.Id()].tags, value.tags...)

		// If the root package is not same as the current package, then the root package remediates
		// the current package
		if pkg.Id() != value.pkg.Id() {
			groupedRemediationPackages[pkg.Id()].remediates = append(groupedRemediationPackages[pkg.Id()].remediates, value)
		}
	}

	// Sort the remediated packages by score
	for _, pkg := range groupedRemediationPackages {
		slices.SortFunc(pkg.remediates, func(a, b *summaryReporterRemediationData) int {
			return cmp.Compare(b.score, a.score)
		})
	}

	remediationPackages := make([]*summaryReporterRemediationData, 0)
	for _, rd := range groupedRemediationPackages {
		remediationPackages = append(remediationPackages, rd)
	}

	slices.SortFunc(remediationPackages, func(a, b *summaryReporterRemediationData) int {
		return cmp.Compare(b.score, a.score)
	})

	return remediationPackages
}

func (r *summaryReporter) renderRemediationAdvice() {
	if len(r.remediationScores) == 0 {
		fmt.Println(text.BgGreen.Sprint(" No risky libraries identified "))
		return
	}

	fmt.Println(text.Bold.Sprint(fmt.Sprintf("Top %d libraries to fix ...", r.config.MaxAdvice)))
	fmt.Println()

	tbl := table.NewWriter()
	tbl.SetOutputMirror(os.Stdout)
	tbl.SetStyle(table.StyleLight)

	var sortedPackages []*summaryReporterRemediationData
	if r.config.GroupByDirectDependency {
		sortedPackages = r.sortedRemediationsGroupByDirectDependency()
	} else {
		sortedPackages = r.sortedRemediations()
	}

	r.addRemediationAdviceTableRows(tbl, sortedPackages, r.config.MaxAdvice)
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

func (r *summaryReporter) addRemediationAdviceTableRows(tbl table.Writer,
	sortedPackages []*summaryReporterRemediationData, maxAdvice int) {
	tbl.AppendHeader(table.Row{"Ecosystem", "Package", "Latest", "Impact Score", "Vuln Risk"})

	// Re-use the formatting logic within this function boundary
	formatTags := func(tags []string) string {
		tagText := ""

		for _, t := range tags {
			tagText += text.BgMagenta.Sprint(" "+t+" ") + " "
		}

		return tagText
	}

	for idx, sp := range sortedPackages {
		if idx >= maxAdvice {
			break
		}

		// Add the package as a table row
		tbl.AppendRow(table.Row{
			string(sp.pkg.Ecosystem),
			r.packageNameForRemediationAdvice(sp.pkg) + " " + r.slsaTagFor(sp.pkg),
			r.packageUpdateVersionForRemediationAdvice(sp.pkg),
			sp.score,
			r.packageVulnerabilityRiskText(sp.pkg),
		})

		// Here things change. We check if we are grouping by top level dependency
		// in which case we also add the packages that are expected to be remediated
		// by updating the direct dependency
		if len(sp.remediates) > 0 {
			uniqueTags := []string{}
			for _, rd := range sp.remediates {
				for _, pt := range rd.tags {
					if utils.FindInSlice(uniqueTags, pt) == -1 {
						uniqueTags = append(uniqueTags, pt)
					}
				}
			}

			tbl.AppendRow(table.Row{
				"", formatTags(uniqueTags), "", "",
				r.packageVulnerabilitySampleText(sp.pkg),
			})

			remediatesSample := sp.remediates[0:slices.Min([]int{len(sp.remediates), 5})]

			// This is a grouped dependency so we will render the children
			for _, rd := range remediatesSample {
				remediatedPkgName := text.Faint.Sprint(r.packageNameForRemediationAdvice(rd.pkg))
				vulnRisk := r.packageVulnerabilityRiskText(rd.pkg)
				vulnRiskSample := r.packageVulnerabilitySampleText(rd.pkg)

				if vulnRiskSample != "" {
					vulnRisk = fmt.Sprintf("%s (%s)", vulnRisk, vulnRiskSample)
				}

				tbl.AppendRow(table.Row{
					"", remediatedPkgName, "", "", vulnRisk,
				})
			}

			if len(sp.remediates) > len(remediatesSample) {
				tbl.AppendRow(table.Row{
					"", fmt.Sprintf("... and %d more", len(sp.remediates)-len(remediatesSample)), "", "", "",
				})
			}
		} else {
			// This is a direct dependency or do not remediate anything else (not grouped)
			tbl.AppendRow(table.Row{
				"", formatTags(sp.tags), "", "",
				r.packageVulnerabilitySampleText(sp.pkg),
			})

			pathToRoot := text.Faint.Sprint(r.pathToPackageRoot(sp.pkg))
			if pathToRoot != "" {
				tbl.AppendRow(table.Row{
					"", pathToRoot, "", "", "",
				})
			}
		}

		tbl.AppendSeparator()
	}
}

func (r *summaryReporter) packageVulnerabilityRiskText(pkg *models.Package) string {
	if _, ok := r.vulnerabilityInfo[pkg.Id()]; !ok {
		return text.BgGreen.Sprint(" None ")
	}

	vulnData := r.vulnerabilityInfo[pkg.Id()]

	if len(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL]) > 0 {
		return text.BgHiRed.Sprint(" Critical ")
	}

	if len(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskHIGH]) > 0 {
		return text.BgRed.Sprint(" High ")
	}

	if len(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM]) > 0 {
		return text.BgYellow.Sprint(" Medium ")
	}

	if len(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskLOW]) > 0 {
		return text.BgBlue.Sprint(" Low ")
	}

	return text.BgWhite.Sprint(" Unknown ")
}

func (r *summaryReporter) packageVulnerabilitySampleText(pkg *models.Package) string {
	if _, ok := r.vulnerabilityInfo[pkg.Id()]; !ok {
		return ""
	}

	vulnData := r.vulnerabilityInfo[pkg.Id()]

	textTemplateFunc := func(s string, c int) string {
		text := s
		if c > 1 {
			text += fmt.Sprintf(" + %d", c-1)
		}

		return text
	}

	if len(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL]) > 0 {
		return textTemplateFunc(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL][0],
			len(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL]))
	}

	if len(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskHIGH]) > 0 {
		return textTemplateFunc(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskHIGH][0],
			len(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskHIGH]))
	}

	if len(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM]) > 0 {
		return textTemplateFunc(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM][0],
			len(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM]))
	}

	if len(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskLOW]) > 0 {
		return textTemplateFunc(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskLOW][0],
			len(vulnData.vulnerabilities[insightapi.PackageVulnerabilitySeveritiesRiskLOW]))
	}

	return ""
}

func (r *summaryReporter) packageNameForRemediationAdvice(pkg *models.Package) string {
	return fmt.Sprintf("%s@%s", pkg.PackageDetails.Name,
		pkg.PackageDetails.Version)
}

func (r *summaryReporter) slsaTagFor(pkg *models.Package) string {
	var slsaProvenance *models.Provenance
	for _, p := range pkg.GetProvenances() {
		if p.Type == models.ProvenanceTypeSlsa {
			slsaProvenance = p
			break
		}
	}

	if slsaProvenance != nil {
		if slsaProvenance.Verified {
			return text.BgGreen.Sprint(" slsa: verified ")
		} else {
			return text.BgRed.Sprint(" slsa: unverified ")
		}
	}

	return ""
}

func (r *summaryReporter) packageUpdateVersionForRemediationAdvice(pkg *models.Package) string {
	insight := utils.SafelyGetValue(pkg.Insights)
	insightsCurrentVersion := utils.SafelyGetValue(insight.PackageCurrentVersion)

	if insightsCurrentVersion == "" {
		return "Not Available"
	}

	sver, _ := semver.Diff(pkg.PackageDetails.Version, insightsCurrentVersion)
	if sver.IsNone() {
		return "-"
	}

	return insightsCurrentVersion
}

func (r *summaryReporter) vulnSummaryStatement() string {
	return fmt.Sprintf("%d critical, %d high and %d other vulnerabilities were identified",
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

func (r *summaryReporter) provenanceStatement() string {
	return fmt.Sprintf("Provenance: %d verified, %d unverified, %d missing",
		r.summary.provenance.verified, r.summary.provenance.unverified,
		r.summary.provenance.none)
}

func (r *summaryReporter) malwareAnalysisStatement() string {
	return fmt.Sprintf("%d/%d libraries were actively scanned for malware",
		r.summary.malware.scanned, r.summary.packages)
}

func (r *summaryReporter) majorVersionDriftStatement() string {
	return fmt.Sprintf("%d libraries are out of date with major version drift in direct dependencies",
		r.summary.metrics.drifts)
}

func (r *summaryReporter) exceptionsCountStatement() string {
	return fmt.Sprintf("%d libraries are exempted from analysis through exception rules",
		exceptions.ActiveCount())
}

func (r *summaryReporter) pathToPackageRoot(pkg *models.Package) string {
	path := strings.Builder{}

	dg := pkg.GetDependencyGraph()
	if dg == nil {
		return path.String()
	}

	if dg.IsRoot(pkg) {
		return path.String()
	}

	pathToRoot := pkg.Manifest.DependencyGraph.PathToRoot(pkg)
	if len(pathToRoot) == 0 {
		return path.String()
	}

	path.WriteString(fmt.Sprintf(" ... [%d] > ", len(pathToRoot)-1))

	rootPkg := pathToRoot[len(pathToRoot)-1]
	path.WriteString(rootPkg.GetName() + "@" + rootPkg.GetVersion())

	return path.String()
}
