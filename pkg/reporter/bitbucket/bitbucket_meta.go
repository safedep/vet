package bitbucket

import (
	"fmt"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/reporter"
)

type DataPoint string

const (
	dataPointMaliciousPackages  DataPoint = "Malicious Pacakges"
	dataPointVulnerabilities    DataPoint = "Vulnerabilities"
	dataPointSuspiciousPackages DataPoint = "Suspicious Pacakges"
	dataPointViolations         DataPoint = "Violations"
	dataPointThreats            DataPoint = "Theats"
)

func newBitBucketCodeInsightsReport(tool reporter.ToolMetadata) *CodeInsightsReport {
	return &CodeInsightsReport{
		Title:      "SafeDep Vet Scan",
		Details:    fmt.Sprintf("Scan summary from %s %s", tool.VendorName, tool.Name),
		ReportType: ReportTypeSecurity,
		Reporter:   fmt.Sprintf("%s/%s", tool.VendorName, tool.Name),
		Result:     ReportResultPassed,
		Data:       make([]*CodeInsightsData, 0),
	}
}

func (r *CodeInsightsReport) addManifest(manifest *models.PackageManifest) {
	for _, pkg := range manifest.Packages {
		var vulneravilitiesCnt = len(utils.SafelyGetValue(pkg.Insights.Vulnerabilities))
		upsertDataPointInReport(r, vulneravilitiesCnt, dataPointVulnerabilities)

		malwareInfo := utils.SafelyGetValue(pkg.MalwareAnalysis)
		if malwareInfo.IsMalware {
			upsertDataPointInReport(r, 1, dataPointMaliciousPackages)
		}
		if malwareInfo.IsSuspicious {
			upsertDataPointInReport(r, 1, dataPointSuspiciousPackages)
		}
	}
}

func (r *CodeInsightsReport) addAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	if event.IsFilterMatch() {
		upsertDataPointInReport(r, 1, dataPointViolations)
	} else if event.IsLockfilePoisoningSignal() {
		upsertDataPointInReport(r, 1, dataPointThreats)
	}
}

func upsertDataPointInReport(report *CodeInsightsReport, value int, dataPoint DataPoint) {
	found := false
	for _, data := range report.Data {
		if data.Title == string(dataPoint) {
			count := data.Value.(int)
			data.Value = count + value
			found = true
			break
		}
	}

	if !found {
		// using configurable logic / rule, make the Report FAILED
		markReportFailed(report, dataPoint)

		report.Data = append(report.Data, &CodeInsightsData{
			Title: string(dataPoint),
			Type:  DataTypeNumber,
			Value: value,
		})
	}
}

func markReportFailed(report *CodeInsightsReport, dataPoint DataPoint) {
	if dataPoint == dataPointSuspiciousPackages {
		// if only for suspicious packages, we dont mark the Reprort as "FAILED"
		return
	}

	// else for all other cases, i.e found vulnerabilty, threat, vilations or verified malicious package
	// we make the report as "FAILED"
	report.Result = ReportResultFailed
}
