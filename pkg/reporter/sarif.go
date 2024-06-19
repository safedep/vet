package reporter

import (
	"fmt"
	"os"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/checks"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/reporter/markdown"
)

// We will generate SARIF report for integration with
// different consumer tools. The design goal is to
// publish the following information in order of priority:
//
// 1. Policy violations
// 2. Package vulnerabilities
//
// We will not publish all package information. JSON
// report should be used for that purpose.

type SarifToolMetadata struct {
	Name    string
	Version string
}

type SarifReporterConfig struct {
	Tool SarifToolMetadata
	Path string
}

type sarifReporter struct {
	config          SarifReporterConfig
	report          *sarif.Report
	run             *sarif.Run
	rulesCache      map[string]bool
	violationsCache map[string]bool
}

func NewSarifReporter(config SarifReporterConfig) (Reporter, error) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		return nil, err
	}

	run := sarif.NewRunWithInformationURI(config.Tool.Name,
		"https://github.com/safedep/vet")

	run.Tool.Driver.Version = &config.Tool.Version
	run.Tool.Driver.Properties = sarif.Properties{
		"name":    config.Tool.Name,
		"version": config.Tool.Version,
	}

	return &sarifReporter{
		config:          config,
		report:          report,
		run:             run,
		rulesCache:      make(map[string]bool),
		violationsCache: make(map[string]bool),
	}, nil
}

func (r *sarifReporter) Name() string {
	return "sarif"
}

func (r *sarifReporter) AddManifest(manifest *models.PackageManifest) {
	a := sarif.NewArtifact().
		WithLocation(sarif.NewSimpleArtifactLocation(manifest.GetDisplayPath()))
	r.run.Artifacts = append(r.run.Artifacts, a)
}

func (r *sarifReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	r.recordFilterMatchEvent(event)
	r.recordThreatEvent(event)
}

func (r *sarifReporter) AddPolicyEvent(event *policy.PolicyEvent) {
}

func (r *sarifReporter) Finish() error {
	logger.Infof("Writing SARIF report to %s", r.config.Path)

	fd, err := os.OpenFile(r.config.Path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	defer fd.Close()

	r.report.AddRun(r.run)
	return r.report.Write(fd)
}

func (r *sarifReporter) recordThreatEvent(event *analyzer.AnalyzerEvent) {
	if !event.IsLockfilePoisoningSignal() {
		return
	}

	// TODO: Handle threat events in a generic way
}

func (r *sarifReporter) recordFilterMatchEvent(event *analyzer.AnalyzerEvent) {
	if !event.IsFilterMatch() {
		return
	}

	if (event.Package == nil) || (event.Package.Manifest == nil) || (event.Filter == nil) {
		logger.Warnf("SARIF: Invalid event: missing package or manifest or filter")
		return
	}

	if _, ok := r.rulesCache[event.Filter.GetName()]; !ok {
		rule := sarif.NewRule(event.Filter.GetName())
		rule.ShortDescription = sarif.NewMultiformatMessageString(event.Filter.GetSummary())
		rule.Properties = sarif.Properties{
			"filter": event.Filter.GetValue(),
			"type":   event.Filter.GetCheckType(),
		}

		r.run.Tool.Driver.Rules = append(r.run.Tool.Driver.Rules, rule)
		r.rulesCache[event.Filter.GetName()] = true
	}

	uniqueInstance := fmt.Sprintf("%s/%s/%s",
		event.Package.GetName(), event.Manifest.GetDisplayPath(), event.Filter.GetName())
	if _, ok := r.violationsCache[uniqueInstance]; ok {
		return
	}

	r.violationsCache[uniqueInstance] = true

	result := sarif.NewRuleResult(event.Filter.GetName())

	result.WithLevel("error")
	result.WithMessage(r.buildFilterResultMessageMarkdown(event))

	pLocation := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation(event.Manifest.GetDisplayPath()))
	result.Locations = append(result.Locations, sarif.NewLocation().WithPhysicalLocation(pLocation))

	r.run.AddResult(result)
}

func (r *sarifReporter) buildFilterResultMessageMarkdown(event *analyzer.AnalyzerEvent) *sarif.Message {
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
		WithText(md.Build())

	return msg
}
