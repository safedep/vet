package bitbucket

import (
	"fmt"
	"strings"

	"github.com/safedep/dry/utils"

	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/malysis"
	"github.com/safedep/vet/pkg/models"
)

func newBitBucketAnnotationForPackage(pkg *models.Package) []*CodeInsightsAnnotation {
	annotations := make([]*CodeInsightsAnnotation, 0)

	if pkg == nil || pkg.Insights == nil || pkg.Manifest == nil {
		return annotations
	}

	vulnerabilities := utils.SafelyGetValue(pkg.Insights.Vulnerabilities)
	packagePath := pkg.Manifest.GetSource().GetPath()

	for _, v := range vulnerabilities {
		title := utils.SafelyGetValue(v.Summary)
		vulId := utils.SafelyGetValue(v.Id)

		// common in PYSEC vuls
		if title == "" {
			title = fmt.Sprintf("Package %s is vulnerable to %s", pkg.Name, vulId)
		}

		annotations = append(annotations, &CodeInsightsAnnotation{
			Title:          title,
			AnnotationType: AnnotationTypeVulnerability,
			Summary:        fmt.Sprintf("Vulnerability in %s@%s", pkg.GetName(), pkg.GetVersion()),
			Severity:       vulnerabilitySeverityToBitBucketAnnotationSeverity(v),
			FilePath:       packagePath,
			ExternalID:     vulId,
		})
	}

	malwareInfo := utils.SafelyGetValue(pkg.MalwareAnalysis)
	threatLink := malysis.ReportURL(strings.TrimPrefix(malwareInfo.Id(), "SD-MAL-"))

	if malwareInfo.IsMalware {
		annotations = append(annotations, &CodeInsightsAnnotation{
			Title:          fmt.Sprintf("Malware Package %s@%s", pkg.Name, pkg.Version),
			AnnotationType: AnnotationTypeCodeSmell,
			Summary:        fmt.Sprintf("Package %s@%s is malicious", pkg.Name, pkg.Version),
			Severity:       AnnotationSeverityCritical,
			FilePath:       packagePath,
			Link:           threatLink,
		})
	}
	if malwareInfo.IsSuspicious {
		annotations = append(annotations, &CodeInsightsAnnotation{
			Title:          fmt.Sprintf("Suspicious Package %s@%s", pkg.Name, pkg.Version),
			AnnotationType: AnnotationTypeCodeSmell,
			Summary:        fmt.Sprintf("Package %s@%s is suspicious", pkg.Name, pkg.Version),
			Severity:       AnnotationSeverityHigh,
			FilePath:       packagePath,
			Link:           threatLink,
		})
	}

	return annotations
}

func newBitBucketAnnotationForAnalyzerEvent(event *analyzer.AnalyzerEvent) *CodeInsightsAnnotation {
	if event.Package.Manifest == nil {
		return nil
	}

	title := event.Filter.GetSummary()
	if title == "" {
		title = fmt.Sprintf("Filter %s matched for %s@%s", event.Filter.Name, event.Package.Name, event.Package.Version)
	}

	summary := event.Filter.GetDescription()
	if summary == "" {
		summary = fmt.Sprintf("Source: %s", event.Source)
	}

	return &CodeInsightsAnnotation{
		Title:          title,
		AnnotationType: AnnotationTypeCodeSmell,
		Summary:        summary,
		Severity:       AnnotationSeverityMedium, // Default severity for policy violations
		FilePath:       event.Package.Manifest.Source.Path,
		ExternalID:     utils.NewUniqueId(),
	}
}

func vulnerabilitySeverityToBitBucketAnnotationSeverity(vuln insightapi.PackageVulnerability) AnnotationSeverity {
	severities := utils.SafelyGetValue(vuln.Severities)
	if len(severities) == 0 {
		return AnnotationSeverityMedium
	}

	switch utils.SafelyGetValue(severities[0].Risk) {
	case insightapi.PackageVulnerabilitySeveritiesRiskCRITICAL:
		return AnnotationSeverityCritical
	case insightapi.PackageVulnerabilitySeveritiesRiskHIGH:
		return AnnotationSeverityHigh
	case insightapi.PackageVulnerabilitySeveritiesRiskMEDIUM:
		return AnnotationSeverityMedium
	case insightapi.PackageVulnerabilitySeveritiesRiskLOW:
		return AnnotationSeverityLow
	default:
		return AnnotationSeverityMedium
	}
}
