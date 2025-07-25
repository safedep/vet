package reporter

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/safedep/dry/log"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/checks"
	jsonreportspec "github.com/safedep/vet/gen/jsonreport"
	specmodels "github.com/safedep/vet/gen/models"
	"github.com/safedep/vet/gen/violations"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/malysis"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/readers"
	"github.com/safedep/vet/pkg/reporter/markdown"
)

const (
	lockfilePoisoningReference = "https://safedep.substack.com/p/lockfile-poisoning-an-attack-vector"
	markdownSummaryReportTitle = "vet Summary Report"
)

type MarkdownSummaryReporterConfig struct {
	Tool                   ToolMetadata
	Path                   string
	ReportTitle            string
	IncludeMalwareAnalysis bool
	ActiveMalwareAnalysis  bool
}

type vetResultInternalModel struct {
	violations map[checks.CheckType][]*violations.Violation
	packages   []*jsonreportspec.PackageReport
	manifests  map[string]*jsonreportspec.PackageManifestReport
	threats    map[jsonreportspec.ReportThreat_ReportThreatId][]*jsonreportspec.ReportThreat
}

type markdownSummaryPackageMalwareInfo struct {
	ecosystem    string
	name         string
	version      string
	isMalicious  bool
	isSuspicious bool
	referenceURL string
}

type markdownSummaryMalwareInfo struct {
	malwareInfo              map[string]*markdownSummaryPackageMalwareInfo
	haveMalwarAnalysisReport int
	missingMalwareAnalysis   int
	maliciousPackages        int
	suspiciousPackages       int
}

type markdownSummaryReporter struct {
	config         MarkdownSummaryReporterConfig
	jsonReportPath string
	jsonReporter   Reporter
	malwareInfo    *markdownSummaryMalwareInfo
}

// NewMarkdownSummaryReporter creates a new markdown summary reporter. This reporter
// is suitable for generating markdown reports intended for PR comments.
func NewMarkdownSummaryReporter(config MarkdownSummaryReporterConfig) (Reporter, error) {
	tmpFile, err := os.CreateTemp("", "vet-md-json-spec-*")
	if err != nil {
		return nil, err
	}

	// TOCTOU here but not a big risk
	// We will delete this file on Finish()
	tmpFile.Close()

	jsonReporter, err := NewJsonReportGenerator(JsonReportingConfig{
		Path: tmpFile.Name(),
		Tool: config.Tool,
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
		malwareInfo: &markdownSummaryMalwareInfo{
			malwareInfo: make(map[string]*markdownSummaryPackageMalwareInfo),
		},
	}, nil
}

func (r *markdownSummaryReporter) Name() string {
	return "Markdown Summary Reporter"
}

func (r *markdownSummaryReporter) AddManifest(manifest *models.PackageManifest) {
	r.jsonReporter.AddManifest(manifest)

	err := readers.NewManifestModelReader(manifest).EnumPackages(func(pkg *models.Package) error {
		err := r.malwareInfo.handlePackage(pkg)
		if err != nil {
			logger.Errorf("[Markdown Reporter]: Failed to handle malware info for package %s: %v",
				pkg.GetName(), err)
		}

		return nil
	})
	if err != nil {
		logger.Errorf("[Markdown Reporter]: Failed to enumerate packages in manifest %s: %v",
			manifest.GetPath(), err)
	}
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
	err = utils.FromPbJson(bytes.NewReader(data), &report)
	if err != nil {
		return fmt.Errorf("failed to parse JSON report: %w", err)
	}

	builder := markdown.NewMarkdownBuilder()
	err = r.buildMarkdownReport(builder, &report)
	if err != nil {
		return fmt.Errorf("failed to build markdown report: %w", err)
	}

	err = os.WriteFile(r.config.Path, []byte(builder.Build()), 0o600)
	if err != nil {
		return fmt.Errorf("failed to write markdown summary to file: %w", err)
	}

	return nil
}

func (r *markdownSummaryReporter) buildMarkdownReport(builder *markdown.MarkdownBuilder,
	report *jsonreportspec.Report,
) error {
	internalModel, err := r.buildInternalModel(report)
	if err != nil {
		return fmt.Errorf("failed to build internal data model: %w", err)
	}

	builder.AddHeader(1, r.config.ReportTitle)
	builder.AddParagraph("This report is generated by [vet](https://github.com/safedep/vet)")

	err = r.addPolicyCheckSection(builder, internalModel)
	if err != nil {
		return fmt.Errorf("failed to add policy section: %w", err)
	}

	// Add note in the report some suspicious packages are found and human review is required.
	if r.malwareInfo.suspiciousPackages > 0 {
		builder.AddParagraph(fmt.Sprintf("\n%s %d packages are identified as suspicious. Human review is recommended.", markdown.EmojiWarning, r.malwareInfo.suspiciousPackages))
	}

	err = r.addThreatsSection(builder, internalModel)
	if err != nil {
		return fmt.Errorf("failed to add threats section: %w", err)
	}

	if r.config.IncludeMalwareAnalysis {
		err = r.addMalwareAnalysisReportSection(builder)
		if err != nil {
			return fmt.Errorf("failed to add malware analysis section: %w", err)
		}
	}

	err = r.addChangedPackageSection(builder, internalModel)
	if err != nil {
		return fmt.Errorf("failed to add changed package section: %w", err)
	}

	err = r.addViolationSection(builder, internalModel)
	if err != nil {
		return fmt.Errorf("failed to add violations section: %w", err)
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

			internalModel.violations[violation.GetCheckType()] = append(internalModel.violations[violation.GetCheckType()], violation)
		}

		appendThreats(pkg.GetThreats())
	}

	return internalModel, nil
}

func (r *markdownSummaryReporter) addPolicyCheckSection(builder *markdown.MarkdownBuilder,
	internalModel *vetResultInternalModel,
) error {
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
	internalModel *vetResultInternalModel,
) error {
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

			builder.AddBulletPoint(fmt.Sprintf("%s Found in %s `%s`, %s. Refer to [this](%s) for more details",
				markdown.EmojiWarning,
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
	internalModel *vetResultInternalModel,
) error {
	if len(internalModel.packages) == 0 {
		return nil
	}

	section := builder.StartCollapsibleSection("Changed Packages")
	section.Builder().AddHeader(2, "Changed Packages")

	for _, pkg := range internalModel.packages {
		pkgModel := pkg.GetPackage()
		if pkgModel == nil {
			log.Warnf("pkgModel is unexpectedly nil")
			continue
		}

		statusEmoji := markdown.EmojiWhiteCheckMark
		if len(pkg.GetViolations()) > 0 {
			statusEmoji = markdown.EmojiWarning
		}

		section.Builder().AddBulletPoint(fmt.Sprintf("%s [`%s`] `%s@%s`",
			statusEmoji,
			pkgModel.GetEcosystem(), pkgModel.GetName(), pkgModel.GetVersion()))
	}

	builder.AddCollapsibleSection(section)
	return nil
}

func (r *markdownSummaryReporter) addViolationSection(builder *markdown.MarkdownBuilder,
	internalModel *vetResultInternalModel,
) error {
	section := builder.StartCollapsibleSection("Policy Violations")
	section.Builder().AddHeader(2, "Packages Violating Policy")

	hasViolations := false

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

		hasViolations = true

		externalReferenceEmojiUrl := fmt.Sprintf("[%s](%s)",
			markdown.EmojiLink,
			r.getPackageExternalReferenceUrl(pkgModel))

		section.Builder().AddHeader(3, fmt.Sprintf("[%s] `%s@%s` %s",
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

				section.Builder().AddBulletPoint(fmt.Sprintf(":arrow_right: Found in manifest `%s`", path))
			}
		}

		for _, v := range packageViolations {
			section.Builder().AddBulletPoint(fmt.Sprintf(":warning: %s", v.GetFilter().GetSummary()))
		}

		advices := pkg.GetAdvices()
		for _, advice := range advices {
			advSummary, err := r.getAdviceSummary(advice)
			if err != nil {
				continue
			}

			section.Builder().AddBulletPoint(fmt.Sprintf(":zap: %s", advSummary))
		}
	}

	if hasViolations {
		builder.AddCollapsibleSection(section)
	}

	return nil
}

func (r *markdownSummaryReporter) addMalwareAnalysisReportSection(builder *markdown.MarkdownBuilder) error {
	malwareInfoTable, err := r.malwareInfo.renderMalwareInfoTable()
	if err != nil {
		return fmt.Errorf("failed to render malware info table: %w", err)
	}

	builder.AddHeader(2, "Malicious Package Analysis")

	if r.config.ActiveMalwareAnalysis {
		builder.AddParagraph("Malicious package analysis was performed using [SafeDep Cloud API](https://docs.safedep.io/cloud/malware-analysis)")
	} else {
		builder.AddParagraph("Active malicious package analysis was disabled. " +
			"Learn more about [enabling active package analysis](https://docs.safedep.io/cloud/malware-analysis)")
	}

	reportSection := builder.StartCollapsibleSection("Malicious Package Analysis Report")
	reportSection.Builder().AddRaw(malwareInfoTable)
	reportSection.Builder().AddParagraph("")

	builder.AddCollapsibleSection(reportSection)

	builder.AddBulletPoint(fmt.Sprintf("%s %d packages have been actively analyzed for malicious behaviour.",
		markdown.EmojiInformationSource, r.malwareInfo.haveMalwarAnalysisReport))

	if r.malwareInfo.maliciousPackages > 0 {
		builder.AddBulletPoint(fmt.Sprintf("%s %d packages are identified as malicious.",
			markdown.EmojiRedCircle, r.malwareInfo.maliciousPackages))
	} else if r.malwareInfo.suspiciousPackages > 0 {
		builder.AddBulletPoint(fmt.Sprintf("%s %d packages are identified as suspicious.",
			markdown.EmojiOrangeCircle, r.malwareInfo.suspiciousPackages))
	} else {
		builder.AddBulletPoint(fmt.Sprintf("%s No malicious packages found.",
			markdown.EmojiWhiteCheckMark))
	}

	if r.malwareInfo.missingMalwareAnalysis > 0 {
		if r.config.ActiveMalwareAnalysis {
			builder.AddQuote("Note: Some of the package analysis jobs may still be running." +
				"Please check back later. Consider increasing the timeout for better coverage.")
		} else {
			builder.AddQuote("Note: Only known malicious packages were reported. " +
				"Consider enabling active package analysis to get more accurate results.")
		}
	}

	return nil
}

func (r *markdownSummaryReporter) getCheckIconByCheckType(internalModel *vetResultInternalModel,
	ct checks.CheckType,
) string {
	if _, ok := internalModel.violations[ct]; !ok {
		return markdown.EmojiWhiteCheckMark
	} else {
		return markdown.EmojiCrossMark
	}
}

func (r *markdownSummaryReporter) getCheckIconForThreats(internalModel *vetResultInternalModel) string {
	if len(internalModel.threats) == 0 {
		return markdown.EmojiWhiteCheckMark
	} else {
		return markdown.EmojiCrossMark
	}
}

func (r *markdownSummaryReporter) getAdviceSummary(adv *jsonreportspec.RemediationAdvice) (string, error) {
	switch adv.Type {
	case jsonreportspec.RemediationAdviceType_UpgradePackage:
		if adv.GetTargetPackageVersion() != "" {
			return fmt.Sprintf("Upgrade to %s@%s", adv.GetTargetPackageName(),
				adv.GetTargetPackageVersion()), nil
		} else {
			// We don't have a specific version to upgrade to. We should not given
			// a generic advice to upgrade to latest version.
		}
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

// Update the local cache of malware analysis stats
func (m *markdownSummaryMalwareInfo) handlePackage(pkg *models.Package) error {
	ma := pkg.GetMalwareAnalysisResult()
	if ma == nil {
		m.missingMalwareAnalysis++
		return nil
	}

	if _, ok := m.malwareInfo[pkg.Id()]; !ok {
		m.haveMalwarAnalysisReport++

		if ma.IsMalware {
			m.maliciousPackages++
		} else if ma.IsSuspicious {
			m.suspiciousPackages++
		}

		m.malwareInfo[pkg.Id()] = &markdownSummaryPackageMalwareInfo{
			ecosystem:    pkg.GetControlTowerSpecEcosystem().String(),
			name:         pkg.GetName(),
			version:      pkg.GetVersion(),
			isMalicious:  ma.IsMalware,
			isSuspicious: ma.IsSuspicious,
			referenceURL: malysis.ReportURL(ma.AnalysisId),
		}
	}

	return nil
}

// Render the malware info cache as markdown table
func (m *markdownSummaryMalwareInfo) renderMalwareInfoTable() (string, error) {
	tbl := table.NewWriter()
	tbl.AppendHeader(table.Row{"Ecosystem", "Package", "Version", "Status", "Report"})

	for _, info := range m.malwareInfo {
		emoji := markdown.EmojiWhiteCheckMark
		if info.isMalicious {
			emoji = markdown.EmojiCrossMark
		} else if info.isSuspicious {
			emoji = markdown.EmojiWarning
		}

		tbl.AppendRow(table.Row{
			info.ecosystem,
			info.name,
			info.version,
			emoji,
			fmt.Sprintf("[%s](%s)", markdown.EmojiLink, info.referenceURL),
		})
	}

	return tbl.RenderMarkdown(), nil
}
