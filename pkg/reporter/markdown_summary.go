package reporter

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/safedep/dry/log"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/checks"
	jsonreportspec "github.com/safedep/vet/gen/jsonreport"
	specmodels "github.com/safedep/vet/gen/models"
	"github.com/safedep/vet/gen/violations"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/reporter/markdown"
)

const (
	lockfilePoisoningReference = "https://safedep.substack.com/p/lockfile-poisoning-an-attack-vector"
	markdownSummaryReportTitle = "vet Summary Report"
)

type MarkdownSummaryReporterConfig struct {
	Path        string
	ReportTitle string
}

type vetResultInternalModel struct {
	violations map[checks.CheckType][]*violations.Violation
	packages   []*jsonreportspec.PackageReport
	manifests  map[string]*jsonreportspec.PackageManifestReport
	threats    map[jsonreportspec.ReportThreat_ReportThreatId][]*jsonreportspec.ReportThreat
}

type markdownSummaryReporter struct {
	config         MarkdownSummaryReporterConfig
	jsonReportPath string
	jsonReporter   Reporter
}

// NewMarkdownSummaryReporter creates a new markdown summary reporter. This reporter
// is suitable for generating markdown reports intended for PR comments.
func NewMarkdownSummaryReporter(config MarkdownSummaryReporterConfig) (Reporter, error) {
	tmpFile, err := os.CreateTemp("", "vet-md-json-spec-*")
	if err != nil {
		return nil, err
	}

	// TOCTOU here but not a big risk
	tmpFile.Close()

	jsonReporter, err := NewJsonReportGenerator(JsonReportingConfig{
		Path: tmpFile.Name(),
	})

	if err != nil {
		return nil, err
	}

	if config.ReportTitle == "" {
		config.ReportTitle = markdownSummaryReportTitle
	}

	return &markdownSummaryReporter{
		config:         config,
		jsonReportPath: tmpFile.Name(),
		jsonReporter:   jsonReporter,
	}, nil
}

func (r *markdownSummaryReporter) Name() string {
	return "Markdown Summary Reporter"
}

func (r *markdownSummaryReporter) AddManifest(manifest *models.PackageManifest) {
	r.jsonReporter.AddManifest(manifest)
}

func (r *markdownSummaryReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	r.jsonReporter.AddAnalyzerEvent(event)
}

func (r *markdownSummaryReporter) AddPolicyEvent(event *policy.PolicyEvent) {
	r.jsonReporter.AddPolicyEvent(event)
}

func (r *markdownSummaryReporter) Finish() error {
	defer os.Remove(r.jsonReportPath)

	err := r.jsonReporter.Finish()
	if err != nil {
		return fmt.Errorf("failed to generate JSON report: %w", err)
	}

	log.Debugf("Generating markdown summary report to %s from JSON report %s",
		r.config.Path, r.jsonReportPath)

	data, err := os.ReadFile(r.jsonReportPath)
	if err != nil {
		return fmt.Errorf("failed to read json report file: %w", err)
	}

	var report jsonreportspec.Report
	err = utils.FromPbJson(strings.NewReader(string(data)), &report)

	if err != nil {
		return fmt.Errorf("failed to parse JSON report: %w", err)
	}

	internalModel, err := r.buildInternalModel(&report)
	if err != nil {
		return fmt.Errorf("failed to build internal data model: %w", err)
	}

	builder := markdown.NewMarkdownBuilder()
	builder.AddHeader(1, r.config.ReportTitle)

	err = r.addPolicyCheckSection(builder, internalModel)
	if err != nil {
		return fmt.Errorf("failed to add policy section: %w", err)
	}

	err = r.addThreatsSection(builder, internalModel)
	if err != nil {
		return fmt.Errorf("failed to add threats section: %w", err)
	}

	err = r.addChangedPackageSection(builder, internalModel)
	if err != nil {
		return fmt.Errorf("failed to add changed package section: %w", err)
	}

	err = r.addViolationSection(builder, internalModel)
	if err != nil {
		return fmt.Errorf("failed to add violations section: %w", err)
	}

	err = os.WriteFile(r.config.Path, []byte(builder.Build()), 0600)
	if err != nil {
		return fmt.Errorf("failed to write markdown summary to file: %w", err)
	}

	return nil
}

func (r *markdownSummaryReporter) buildInternalModel(report *jsonreportspec.Report) (*vetResultInternalModel, error) {
	internalModel := &vetResultInternalModel{
		violations: make(map[checks.CheckType][]*violations.Violation),
		manifests:  make(map[string]*jsonreportspec.PackageManifestReport),
		packages:   make([]*jsonreportspec.PackageReport, 0),
		threats:    make(map[jsonreportspec.ReportThreat_ReportThreatId][]*jsonreportspec.ReportThreat, 0),
	}

	appendThreats := func(threats []*jsonreportspec.ReportThreat) {
		for _, t := range threats {
			if _, ok := internalModel.threats[t.GetId()]; !ok {
				internalModel.threats[t.GetId()] = make([]*jsonreportspec.ReportThreat, 0)
			}

			internalModel.threats[t.GetId()] = append(internalModel.threats[t.GetId()], t)
		}
	}

	manifests := report.GetManifests()
	for _, manifest := range manifests {
		internalModel.manifests[manifest.GetId()] = manifest
		appendThreats(manifest.GetThreats())
	}

	packages := report.GetPackages()
	for _, pkg := range packages {
		internalModel.packages = append(internalModel.packages, pkg)

		packageViolations := pkg.GetViolations()
		for _, violation := range packageViolations {
			if _, ok := internalModel.violations[violation.GetCheckType()]; !ok {
				internalModel.violations[violation.GetCheckType()] = make([]*violations.Violation, 0)
			}

			internalModel.violations[violation.GetCheckType()] =
				append(internalModel.violations[violation.GetCheckType()], violation)
		}

		appendThreats(pkg.GetThreats())
	}

	return internalModel, nil
}

func (r *markdownSummaryReporter) addPolicyCheckSection(builder *markdown.MarkdownBuilder,
	internalModel *vetResultInternalModel) error {
	builder.AddHeader(2, "Policy Checks")

	builder.AddBulletPoint(fmt.Sprintf("%s Vulnerability",
		r.getCheckIconByCheckType(internalModel, checks.CheckType_CheckTypeVulnerability)))
	builder.AddBulletPoint(fmt.Sprintf("%s Malware",
		r.getCheckIconByCheckType(internalModel, checks.CheckType_CheckTypeMalware)))
	builder.AddBulletPoint(fmt.Sprintf("%s License",
		r.getCheckIconByCheckType(internalModel, checks.CheckType_CheckTypeLicense)))
	builder.AddBulletPoint(fmt.Sprintf("%s Popularity",
		r.getCheckIconByCheckType(internalModel, checks.CheckType_CheckTypePopularity)))
	builder.AddBulletPoint(fmt.Sprintf("%s Maintenance",
		r.getCheckIconByCheckType(internalModel, checks.CheckType_CheckTypeMaintenance)))
	builder.AddBulletPoint(fmt.Sprintf("%s Security Posture",
		r.getCheckIconByCheckType(internalModel, checks.CheckType_CheckTypeSecurityScorecard)))
	builder.AddBulletPoint(fmt.Sprintf("%s Threats",
		r.getCheckIconForThreats(internalModel)))

	return nil
}

func (r *markdownSummaryReporter) addThreatsSection(builder *markdown.MarkdownBuilder,
	internalModel *vetResultInternalModel) error {
	if len(internalModel.threats) == 0 {
		return nil
	}

	builder.AddHeader(2, "Threats")
	for threatType, threats := range internalModel.threats {
		builder.AddHeader(3, threatType.String())

		for _, threat := range threats {
			foundOn := ""
			switch threat.GetSubjectType() {
			case jsonreportspec.ReportThreat_Manifest:
				foundOn = "manifest"
			case jsonreportspec.ReportThreat_Package:
				foundOn = "package"
			}

			// Skip if we don't know where it was found. This may happen if there is inconsistency
			// between vet and github-app
			if foundOn == "" {
				continue
			}

			subject := threat.GetSubject()

			/*
				if threat.GetSubjectType() == jsonreportspec.ReportThreat_Manifest {
					if _, ok := r.fileMap[subject]; ok {
						subject = r.fileMap[subject]
					}
				}
			*/

			builder.AddBulletPoint(fmt.Sprintf(":warning: Found in %s `%s`, %s. Refer to [this](%s) for more details",
				foundOn,
				subject,
				threat.GetMessage(),
				lockfilePoisoningReference,
			))
		}
	}

	return nil
}

func (r *markdownSummaryReporter) addChangedPackageSection(builder *markdown.MarkdownBuilder,
	internalModel *vetResultInternalModel) error {
	if len(internalModel.packages) == 0 {
		return nil
	}

	builder.AddHeader(2, "New Packages")

	for _, pkg := range internalModel.packages {
		pkgModel := pkg.GetPackage()
		if pkgModel == nil {
			log.Warnf("pkgModel is unexpectedly nil")
			continue
		}

		statusEmoji := ":white_check_mark:"
		if len(pkg.GetViolations()) > 0 {
			statusEmoji = ":warning:"
		}

		builder.AddBulletPoint(fmt.Sprintf("%s [`%s`] `%s@%s`",
			statusEmoji,
			pkgModel.GetEcosystem(), pkgModel.GetName(), pkgModel.GetVersion()))
	}

	return nil
}

func (r *markdownSummaryReporter) addViolationSection(builder *markdown.MarkdownBuilder,
	internalModel *vetResultInternalModel) error {
	isHeaderAdded := false

	for _, pkg := range internalModel.packages {
		packageViolations := pkg.GetViolations()

		// Skip listing packages without any violation
		if len(packageViolations) == 0 {
			continue
		}

		pkgModel := pkg.GetPackage()
		if pkgModel == nil {
			continue
		}

		// We use this weird logic to ensure we don't end up adding
		// section header if there are no package with violations
		if !isHeaderAdded {
			builder.AddHeader(2, "Packages Violating Policy")
			isHeaderAdded = true
		}

		externalReferenceEmojiUrl := fmt.Sprintf("[:link:](%s)",
			r.getPackageExternalReferenceUrl(pkgModel))

		builder.AddHeader(3, fmt.Sprintf("[%s] `%s@%s` %s",
			pkgModel.GetEcosystem(), pkgModel.GetName(), pkgModel.GetVersion(),
			externalReferenceEmojiUrl))

		manifests := pkg.GetManifests()
		for _, manifestId := range manifests {
			if m, ok := internalModel.manifests[manifestId]; ok {
				path := m.GetPath()

				/*
					if _, ok := r.fileMap[path]; ok {
						path = r.fileMap[path]
					}
				*/

				builder.AddBulletPoint(fmt.Sprintf(":arrow_right: Found in manifest `%s`", path))
			}
		}

		for _, v := range packageViolations {
			builder.AddBulletPoint(fmt.Sprintf(":warning: %s", v.GetFilter().GetSummary()))
		}

		advices := pkg.GetAdvices()
		for _, advice := range advices {
			advSummary, err := r.getAdviceSummary(advice)
			if err != nil {
				continue
			}

			builder.AddBulletPoint(fmt.Sprintf(":zap: %s", advSummary))
		}
	}

	return nil
}

func (r *markdownSummaryReporter) getCheckIconByCheckType(internalModel *vetResultInternalModel,
	ct checks.CheckType) string {
	if _, ok := internalModel.violations[ct]; !ok {
		return ":white_check_mark:"
	} else {
		return ":x:"
	}
}

func (r *markdownSummaryReporter) getCheckIconForThreats(internalModel *vetResultInternalModel) string {
	if len(internalModel.threats) == 0 {
		return ":white_check_mark:"
	} else {
		return ":x:"
	}
}

func (r *markdownSummaryReporter) getAdviceSummary(adv *jsonreportspec.RemediationAdvice) (string, error) {
	switch adv.Type {
	case jsonreportspec.RemediationAdviceType_UpgradePackage:
		return fmt.Sprintf("Upgrade to %s@%s", adv.GetTargetPackageName(),
			adv.GetTargetPackageVersion()), nil
	case jsonreportspec.RemediationAdviceType_AlternatePopularPackage:
		return "Use an alternative package that is popular", nil
	case jsonreportspec.RemediationAdviceType_AlternateSecurePackage:
		return "Use an alternative package that has better security posture", nil
	}

	return "", fmt.Errorf("no advice feasible for %s", adv.Type)
}

func (r *markdownSummaryReporter) getPackageExternalReferenceUrl(pkg *specmodels.Package) string {
	version := pkg.GetVersion()

	// Go specific fix for version
	if pkg.GetEcosystem() == specmodels.Ecosystem_Go {
		version = fmt.Sprintf("v%s", version)
	}

	// Handle RubyGems separately because it doesn't exist in deps.dev
	if pkg.GetEcosystem() == specmodels.Ecosystem_RubyGems {
		// Example: https://rubygems.org/gems/mail/versions/2.8.1
		return fmt.Sprintf("https://rubygems.org/gems/%s/versions/%s",
			url.QueryEscape(pkg.GetName()),
			url.QueryEscape(version))
	}

	return fmt.Sprintf("https://deps.dev/%s/%s/%s",
		url.QueryEscape(strings.ToLower(pkg.GetEcosystem().String())),
		url.QueryEscape(pkg.GetName()),
		url.QueryEscape(version))
}
