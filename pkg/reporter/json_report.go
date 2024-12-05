package reporter

import (
	"os"
	"slices"
	"strings"
	"time"

	"github.com/safedep/dry/utils"
	jsonreportspec "github.com/safedep/vet/gen/jsonreport"
	schema "github.com/safedep/vet/gen/jsonreport"
	modelspec "github.com/safedep/vet/gen/models"
	"github.com/safedep/vet/gen/violations"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/readers"
	"github.com/safedep/vet/pkg/remediations"
	"github.com/safedep/vet/pkg/schemamapper"
)

type JsonReportingConfig struct {
	Path string
}

// Json reporter is built on top of summary reporter to
// provide extended visibility
type jsonReportGenerator struct {
	config       JsonReportingConfig
	remediations remediations.RemediationGenerator

	manifests map[string]*jsonreportspec.PackageManifestReport
	packages  map[string]*jsonreportspec.PackageReport
}

func NewJsonReportGenerator(config JsonReportingConfig) (Reporter, error) {
	return &jsonReportGenerator{
		config:       config,
		remediations: remediations.NewStaticRemediationGenerator(),
		manifests:    make(map[string]*schema.PackageManifestReport),
		packages:     make(map[string]*schema.PackageReport),
	}, nil
}

func (r *jsonReportGenerator) Name() string {
	return "JSON Report Generator"
}

func (r *jsonReportGenerator) AddManifest(manifest *models.PackageManifest) {
	// Eager load the package manifest in the cache
	_ = r.findPackageManifestReport(manifest)

	err := readers.NewManifestModelReader(manifest).EnumPackages(func(p *models.Package) error {
		// Eager load the package in the cache
		_ = r.findPackageReport(p)

		if !slices.Contains(r.packages[p.Id()].Manifests, manifest.Id()) {
			r.packages[p.Id()].Manifests = append(r.packages[p.Id()].Manifests, manifest.Id())
		}

		return nil
	})

	if err != nil {
		logger.Warnf("Failed to enumerate manifest packages: %v", err)
	}
}

func (r *jsonReportGenerator) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	if event.IsFilterMatch() {
		r.handleFilterEvent(event)
	} else if event.IsLockfilePoisoningSignal() {
		r.handleThreatEvent(event)
	}
}

func (r *jsonReportGenerator) handleThreatEvent(event *analyzer.AnalyzerEvent) {
	if event.Threat == nil {
		return
	}

	if event.Threat.SubjectType == jsonreportspec.ReportThreat_Manifest && event.Manifest == nil {
		return
	}

	if event.Threat.SubjectType == jsonreportspec.ReportThreat_Package && event.Package == nil {
		return
	}

	switch event.Threat.SubjectType {
	case jsonreportspec.ReportThreat_Manifest:
		manifest := r.findPackageManifestReport(event.Manifest)
		manifest.Threats = append(manifest.Threats, event.Threat)

	case jsonreportspec.ReportThreat_Package:
		pkg := r.findPackageReport(event.Package)
		pkg.Threats = append(pkg.Threats, event.Threat)
	}

}

func (r *jsonReportGenerator) handleFilterEvent(event *analyzer.AnalyzerEvent) {
	if event.Package == nil {
		logger.Warnf("Analyzer event with nil package")
		return
	}

	if event.Package.Manifest == nil {
		logger.Warnf("Analyzer event with nil package manifest")
		return
	}

	if event.Filter == nil {
		logger.Warnf("Analyzer event that matched filter but without Filter object")
		return
	}

	// All subsequent operations are on this pkg
	pkg := r.findPackageReport(event.Package)

	// We avoid duplicate violation for a package. Duplicates can occur because same package
	// is in multiple manifests hence raising same violation
	v := utils.FindAnyWith(pkg.Violations, func(item **violations.Violation) bool {
		return ((*item).GetFilter().GetName() == event.Filter.GetName())
	})
	if v != nil {
		return
	}

	// Fall through here to associate a Violation and a RemediationAdvice
	violation := &violations.Violation{
		CheckType: event.Filter.GetCheckType(),
		Filter:    event.Filter,
	}

	pkg.Violations = append(pkg.Violations, violation)

	advice, err := r.remediations.Advice(event.Package, violation)
	if err != nil {
		logger.Warnf("Failed to generate remediation for %s due to %v",
			event.Package.ShortName(), err)
	} else {
		pkg.Advices = append(pkg.Advices, advice)
	}
}

func (r *jsonReportGenerator) findPackageManifestReport(manifest *models.PackageManifest) *jsonreportspec.PackageManifestReport {
	manifestId := manifest.Id()
	if _, ok := r.manifests[manifestId]; !ok {
		r.manifests[manifestId] = &jsonreportspec.PackageManifestReport{
			Id:          manifestId,
			SourceType:  string(manifest.GetSource().GetType()),
			Namespace:   manifest.GetSource().GetNamespace(),
			Path:        manifest.GetSource().GetPath(),
			DisplayPath: manifest.GetDisplayPath(),
			Ecosystem:   manifest.GetSpecEcosystem(),
			Threats:     make([]*schema.ReportThreat, 0),
		}
	}

	return r.manifests[manifestId]
}

func (r *jsonReportGenerator) findPackageReport(pkg *models.Package) *jsonreportspec.PackageReport {
	pkgId := pkg.Id()
	if _, ok := r.packages[pkgId]; !ok {
		r.packages[pkgId] = r.buildJsonPackageReportFromPackage(pkg)
	}

	return r.packages[pkgId]
}

func (r *jsonReportGenerator) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *jsonReportGenerator) Finish() error {
	logger.Infof("Generating consolidated Json report: %s", r.config.Path)

	report, err := r.buildSpecReport()
	if err != nil {
		return err
	}

	b, err := utils.ToPbJson(report, "")
	if err != nil {
		return err
	}

	file, err := os.Create(r.config.Path)
	if err != nil {
		return err
	}

	defer file.Close()
	_, err = file.WriteString(b)
	return err
}

func (r *jsonReportGenerator) buildSpecReport() (*schema.Report, error) {
	report := schema.Report{
		Meta: &schema.ReportMeta{
			ToolName:    "vet",
			ToolVersion: "latest",
			CreatedAt:   time.Now().UTC().Format(time.RFC3339),
		},
		Packages:  make([]*schema.PackageReport, 0),
		Manifests: make([]*schema.PackageManifestReport, 0),
	}

	for _, pm := range r.manifests {
		report.Manifests = append(report.Manifests, pm)
	}

	for _, p := range r.packages {
		report.Packages = append(report.Packages, p)
	}

	return &report, nil
}

func (j *jsonReportGenerator) buildJsonPackageReportFromPackage(p *models.Package) *jsonreportspec.PackageReport {
	pkg := &jsonreportspec.PackageReport{
		Package: &modelspec.Package{
			Ecosystem: p.GetSpecEcosystem(),
			Name:      p.GetName(),
			Version:   p.GetVersion(),
		},
		Violations:      make([]*violations.Violation, 0),
		Advices:         make([]*schema.RemediationAdvice, 0),
		Vulnerabilities: make([]*modelspec.InsightVulnerability, 0),
		Licenses:        make([]*modelspec.InsightLicenseInfo, 0),
		Projects:        make([]*modelspec.InsightProjectInfo, 0),
		Threats:         make([]*schema.ReportThreat, 0),
	}

	insights := utils.SafelyGetValue(p.Insights)
	vulns := utils.SafelyGetValue(insights.Vulnerabilities)
	licenses := utils.SafelyGetValue(insights.Licenses)
	projects := utils.SafelyGetValue(insights.Projects)

	for _, vuln := range vulns {
		insightSeverities := utils.SafelyGetValue(vuln.Severities)
		severties := []*modelspec.InsightVulnerabilitySeverity{}

		for _, sev := range insightSeverities {
			mappedSeverity, err := schemamapper.InsightsVulnerabilitySeverityToModelSeverity(&schemamapper.InsightsVulnerabilitySeverity{
				Type:  sev.Type,
				Risk:  sev.Risk,
				Score: sev.Score,
			})

			if err != nil {
				logger.Errorf("Failed to convert InsightAPI schema to model spec: %v", err)
				continue
			}

			severties = append(severties, mappedSeverity)
		}

		pkg.Vulnerabilities = append(pkg.Vulnerabilities, &modelspec.InsightVulnerability{
			Id:         utils.SafelyGetValue(vuln.Id),
			Title:      utils.SafelyGetValue(vuln.Summary),
			Aliases:    utils.SafelyGetValue(vuln.Aliases),
			Severities: severties,
		})

	}

	for _, license := range licenses {
		pkg.Licenses = append(pkg.Licenses, &modelspec.InsightLicenseInfo{
			Id: string(license),
		})
	}

	// Re-usable function to get project name and url from scorecard
	// when projects are not available in insights
	getProjectFromScorecard := func() (string, string) {
		scorecard := utils.SafelyGetValue(insights.Scorecard)
		content := utils.SafelyGetValue(scorecard.Content)
		repository := utils.SafelyGetValue(content.Repository)

		projectUrl := utils.SafelyGetValue(repository.Name)
		projectName := ""

		parts := strings.SplitN(projectUrl, "/", 2)
		if len(parts) == 2 {
			projectName = parts[1]
		}

		if projectUrl != "" && !strings.HasPrefix(projectUrl, "http") {
			projectUrl = "https://" + projectUrl
		}

		return projectName, projectUrl
	}

	for _, project := range projects {
		stars := utils.SafelyGetValue(project.Stars)
		projectUrl := utils.SafelyGetValue(project.Link)

		pkg.Projects = append(pkg.Projects, &modelspec.InsightProjectInfo{
			Name:  utils.SafelyGetValue(project.Name),
			Stars: int32(stars),
			Url:   projectUrl,
		})
	}

	// Project Url can be empty because we use custom data source
	// for RubyGems. We should copy from scorecard
	if len(projects) == 0 {
		projectName, projectUrl := getProjectFromScorecard()

		if projectUrl != "" {
			pkg.Projects = append(pkg.Projects, &modelspec.InsightProjectInfo{
				Name: projectName,
				Url:  projectUrl,
			})
		}
	}

	if len(pkg.Vulnerabilities) > 0 {
		pkg.Advices = append(pkg.Advices, &schema.RemediationAdvice{
			Type:                          schema.RemediationAdviceType_UpgradePackage,
			TargetAlternatePackageVersion: utils.SafelyGetValue(insights.PackageCurrentVersion),
		})
	}

	return pkg
}
