package reporter

import (
	"fmt"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/checks"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/reporter/markdown"
)

// Internal rules apart from policy violations
const (
	ruleIdVulnerabilityRecord = "vulnerability-record"
	ruleIdMaliciousPackage    = "malicious-package"
)

var internalRules = map[string]struct {
	description string
	properties  sarif.Properties
}{
	ruleIdVulnerabilityRecord: {
		description: "Vulnerability record",
		properties:  sarif.Properties{"type": "vulnerability"},
	},
	ruleIdMaliciousPackage: {
		description: "Malicious package",
		properties:  sarif.Properties{"type": "malicious-package"},
	},
}

type sarifBuilderConfig struct {
	Tool           ToolMetadata
	IncludeVulns   bool
	IncludeMalware bool
}

type sarifBuilder struct {
	config          sarifBuilderConfig
	report          *sarif.Report
	run             *sarif.Run
	rulesCache      map[string]bool
	violationsCache map[string]bool
	vulnCache       map[string]bool
}

const sarifErrorLevel = "error"

func newSarifBuilder(config sarifBuilderConfig) (*sarifBuilder, error) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, err
	}

	run := sarif.NewRunWithInformationURI(config.Tool.Name,
		config.Tool.InformationURI)

	run.Tool.Driver.Version = &config.Tool.Version
	run.Tool.Driver.Properties = sarif.Properties{
		"name":    config.Tool.Name,
		"version": config.Tool.Version,
	}

	// Add the internal rules to the run
	for ruleId, ruleInfo := range internalRules {
		rule := sarif.NewRule(ruleId)
		rule.ShortDescription = sarif.NewMultiformatMessageString(ruleInfo.description)
		rule.Properties = ruleInfo.properties
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, rule)
	}

	// Add the run pointer to the report. We will be updating the run
	// information as we add more results to it.
	report.AddRun(run)

	return &sarifBuilder{
		report:          report,
		run:             run,
		config:          config,
		rulesCache:      make(map[string]bool),
		vulnCache:       make(map[string]bool),
		violationsCache: make(map[string]bool),
	}, nil
}

func (b *sarifBuilder) AddManifest(manifest *models.PackageManifest) {
	a := sarif.NewArtifact().
		WithLocation(sarif.NewSimpleArtifactLocation(manifest.GetDisplayPath()))
	b.run.Artifacts = append(b.run.Artifacts, a)

	for _, pkg := range manifest.GetPackages() {
		if b.config.IncludeVulns {
			b.recordVulnerabilities(pkg)
		}

		if b.config.IncludeMalware {
			b.recordMalware(pkg)
		}
	}
}

func (b *sarifBuilder) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	b.recordFilterMatchEvent(event)
	b.recordThreatEvent(event)
}

// This should be idempotent. We should not mutate the state here
func (b *sarifBuilder) GetSarifReport() (*sarif.Report, error) {
	return b.report, nil
}

func (b *sarifBuilder) recordThreatEvent(event *analyzer.AnalyzerEvent) {
	if !event.IsLockfilePoisoningSignal() {
		return
	}

	// TODO: Handle threat events in a generic way
}

func (b *sarifBuilder) recordFilterMatchEvent(event *analyzer.AnalyzerEvent) {
	if !event.IsFilterMatch() {
		return
	}

	if (event.Package == nil) || (event.Manifest == nil) || (event.Filter == nil) {
		logger.Warnf("SARIF: Invalid event: missing package or manifest or filter")
		return
	}

	if _, ok := b.rulesCache[event.Filter.GetName()]; !ok {
		rule := sarif.NewRule(event.Filter.GetName())
		rule.ShortDescription = sarif.NewMultiformatMessageString(event.Filter.GetSummary())
		rule.Properties = sarif.Properties{
			"filter": event.Filter.GetValue(),
			"type":   event.Filter.GetCheckType(),
		}

		b.run.Tool.Driver.Rules = append(b.run.Tool.Driver.Rules, rule)
		b.rulesCache[event.Filter.GetName()] = true
	}

	uniqueInstance := fmt.Sprintf("%s/%s/%s",
		event.Package.GetName(), event.Manifest.GetDisplayPath(), event.Filter.GetName())
	if _, ok := b.violationsCache[uniqueInstance]; ok {
		return
	}

	b.violationsCache[uniqueInstance] = true

	result := sarif.NewRuleResult(event.Filter.GetName())
	result.WithLevel(sarifErrorLevel)
	result.WithMessage(b.buildFilterResultMessageMarkdown(event))

	pLocation := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation(event.Manifest.GetDisplayPath()))
	result.Locations = append(result.Locations, sarif.NewLocation().WithPhysicalLocation(pLocation))

	b.run.AddResult(result)
}

func (b *sarifBuilder) buildFilterResultMessageMarkdown(event *analyzer.AnalyzerEvent) *sarif.Message {
	md := markdown.NewMarkdownBuilder()

	md.AddHeader(2, "Policy Violation")
	md.AddParagraph(fmt.Sprintf("Package `%s` violates policy `%s`.",
		event.Package.GetName(), event.Filter.GetName()))

	insights := utils.SafelyGetValue(event.Package.Insights)

	if event.Filter.GetCheckType() == checks.CheckType_CheckTypeVulnerability {
		md.AddHeader(3, "Vulnerabilities")

		vulns := utils.SafelyGetValue(insights.Vulnerabilities)
		for _, vuln := range vulns {
			vid := utils.SafelyGetValue(vuln.Id)
			md.AddBulletPoint(fmt.Sprintf("[%s](%s): %s",
				vid,
				vulnIdToLink(vid),
				utils.SafelyGetValue(vuln.Summary)))
		}

	} else if event.Filter.GetCheckType() == checks.CheckType_CheckTypeLicense {
		md.AddHeader(3, "Licenses")

		licenses := utils.SafelyGetValue(insights.Licenses)
		for _, license := range licenses {
			md.AddBulletPoint(string(license))
		}
	} else if event.Filter.GetCheckType() == checks.CheckType_CheckTypePopularity {
		projects := utils.SafelyGetValue(insights.Projects)

		if len(projects) > 0 {
			projectSource := utils.SafelyGetValue(projects[0].Type)

			if strings.ToLower(projectSource) == "github" {
				md.AddHeader(3, "GitHub Project")
				md.AddBulletPoint(fmt.Sprintf("Name: %s", utils.SafelyGetValue(projects[0].Name)))
				md.AddBulletPoint(fmt.Sprintf("Stars: %d", utils.SafelyGetValue(projects[0].Stars)))
				md.AddBulletPoint(fmt.Sprintf("Forks: %d", utils.SafelyGetValue(projects[0].Forks)))
				md.AddBulletPoint(fmt.Sprintf("Issues: %d", utils.SafelyGetValue(projects[0].Issues)))
				md.AddBulletPoint(fmt.Sprintf("URL: %s", utils.SafelyGetValue(projects[0].Link)))
			}
		}
	}

	// SARIF spec mandates that we provide text in addition to markdown
	msg := sarif.NewMessage().
		WithMarkdown(md.Build()).
		WithText(md.BuildPlainText())

	return msg
}

func (b *sarifBuilder) recordVulnerabilities(pkg *models.Package) {
	if pkg.Insights == nil {
		return
	}

	vulns := utils.SafelyGetValue(pkg.Insights.Vulnerabilities)
	if len(vulns) == 0 {
		return
	}

	for _, vuln := range vulns {
		vulnId := utils.SafelyGetValue(vuln.Id)
		if _, ok := b.vulnCache[vulnId]; ok {
			continue
		}

		b.vulnCache[vulnId] = true

		result := sarif.NewRuleResult(ruleIdVulnerabilityRecord)
		result.WithLevel(sarifErrorLevel)

		vulnerabilitySummary := utils.SafelyGetValue(vuln.Summary)
		if utils.IsEmptyString(vulnerabilitySummary) {
			vulnerabilitySummary = fmt.Sprintf("Package %s@%s is vulnerable to %s",
				pkg.GetName(), pkg.GetVersion(), vulnId)
		} else {
			vulnerabilitySummary = fmt.Sprintf("Package %s@%s is vulnerable to %s. Following details are available:\n%s",
				pkg.GetName(), pkg.GetVersion(), vulnId, vulnerabilitySummary)
		}

		result.WithMessage(sarif.NewMessage().WithText(vulnerabilitySummary))

		pLocation := sarif.NewPhysicalLocation().
			WithArtifactLocation(sarif.NewSimpleArtifactLocation(pkg.Manifest.GetDisplayPath()))
		result.Locations = append(result.Locations, sarif.NewLocation().WithPhysicalLocation(pLocation))

		b.run.AddResult(result)
	}
}

func (b *sarifBuilder) recordMalware(pkg *models.Package) {
	if pkg.MalwareAnalysis == nil {
		return
	}

	malwareAnalysis := utils.SafelyGetValue(pkg.MalwareAnalysis)

	if malwareAnalysis.IsMalware {
		inference := utils.SafelyGetValue(malwareAnalysis.Report.GetInference())
		result := sarif.NewRuleResult(ruleIdMaliciousPackage)
		result.WithLevel(sarifErrorLevel)

		malwareSummary := inference.GetSummary()
		if utils.IsEmptyString(malwareSummary) {
			malwareSummary = fmt.Sprintf("Malicious code in %s (%s)", pkg.GetName(), pkg.Ecosystem)
		}
		result.WithMessage(sarif.NewMessage().WithText(malwareSummary))

		pLocation := sarif.NewPhysicalLocation().
			WithArtifactLocation(sarif.NewSimpleArtifactLocation(pkg.Manifest.GetDisplayPath()))
		result.Locations = append(result.Locations, sarif.NewLocation().WithPhysicalLocation(pLocation))

		b.run.AddResult(result)
	}
}
