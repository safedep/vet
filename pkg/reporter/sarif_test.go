package reporter

import (
	"os"
	"testing"

	"github.com/safedep/vet/gen/checks"
	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
	"github.com/stretchr/testify/assert"
)

var licenses = []insightapi.License{
	"MIT",
	"GPL",
}

var sampleVulnId = "ghsa-123"
var sampleVulnSummary = "sample-vuln-summary"

var sampleProjectName = "project-name"
var sampleProjectType = "GITHUB"
var sampleProjectStars = 100

var events []analyzer.AnalyzerEvent = []analyzer.AnalyzerEvent{
	{
		Type: analyzer.ET_FilterExpressionMatched,
		Filter: &filtersuite.Filter{
			Name:      "sample-filter1",
			Summary:   "sample-summary1",
			Value:     "sample-value1",
			CheckType: checks.CheckType_CheckTypeLicense,
		},
		Manifest: &models.PackageManifest{
			Source: models.PackageManifestSource{
				DisplayPath: "displayPath1",
			},
		},
		Package: &models.Package{
			PackageDetails: models.NewPackageDetail("ecosystem1", "name1", "version1"),
			Manifest: &models.PackageManifest{
				Source: models.PackageManifestSource{
					DisplayPath: "displayPath1",
				},
			},
			Insights: &insightapi.PackageVersionInsight{
				Licenses: &licenses,
			},
		},
	},
	{
		Type: analyzer.ET_FilterExpressionMatched,
		Filter: &filtersuite.Filter{
			Name:      "sample-filter2",
			Summary:   "sample-summary2",
			Value:     "sample-value2",
			CheckType: checks.CheckType_CheckTypeVulnerability,
		},
		Manifest: &models.PackageManifest{
			Source: models.PackageManifestSource{
				DisplayPath: "displayPath1",
			},
		},
		Package: &models.Package{
			PackageDetails: models.NewPackageDetail("ecosystem2", "name2", "version2"),
			Manifest: &models.PackageManifest{
				Source: models.PackageManifestSource{
					DisplayPath: "displayPath1",
				},
			},
			Insights: &insightapi.PackageVersionInsight{
				Vulnerabilities: &[]insightapi.PackageVulnerability{
					{
						Id:      &sampleVulnId,
						Summary: &sampleVulnSummary,
					},
				},
			},
		},
	},
	{
		Type: analyzer.ET_FilterExpressionMatched,
		Filter: &filtersuite.Filter{
			Name:      "sample-filter3",
			Summary:   "sample-summary3",
			Value:     "sample-value3",
			CheckType: checks.CheckType_CheckTypePopularity,
		},
		Manifest: &models.PackageManifest{
			Source: models.PackageManifestSource{
				DisplayPath: "displayPath2",
			},
		},
		Package: &models.Package{
			PackageDetails: models.NewPackageDetail("ecosystem3", "name3", "version3"),
			Manifest: &models.PackageManifest{
				Source: models.PackageManifestSource{
					DisplayPath: "displayPath3",
				},
			},
			Insights: &insightapi.PackageVersionInsight{
				Projects: &[]insightapi.PackageProjectInfo{
					{
						Name:  &sampleProjectName,
						Type:  &sampleProjectType,
						Stars: &sampleProjectStars,
					},
				},
			},
		},
	},
}

func TestSarifReport(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "sarif-reporter-test")
	assert.Nil(t, err)

	defer os.Remove(tmpFile.Name())

	r, err := NewSarifReporter(SarifReporterConfig{
		Tool: SarifToolMetadata{
			Name:    "tool-name",
			Version: "tool-version",
		},
		Path: tmpFile.Name(),
	})

	assert.Nil(t, err)

	for _, event := range events {
		r.AddManifest(event.Manifest)
		r.AddAnalyzerEvent(&event)
	}

	err = r.Finish()
	assert.Nil(t, err)

	s := r.(*sarifReporter)
	assert.Equal(t, "sarif", s.Name())

	assert.Equal(t, 1, len(s.report.Runs))
	assert.Equal(t, len(events), len(s.report.Runs[0].Artifacts))
	assert.Equal(t, len(events), len(s.report.Runs[0].Results))
}

func TestSarifReportMarkdown(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "sarif-reporter-test")
	assert.Nil(t, err)

	defer os.Remove(tmpFile.Name())

	r, err := NewSarifReporter(SarifReporterConfig{
		Tool: SarifToolMetadata{
			Name:    "tool-name",
			Version: "tool-version",
		},
		Path: tmpFile.Name(),
	})

	assert.Nil(t, err)

	for _, event := range events {
		r.AddManifest(event.Manifest)
		r.AddAnalyzerEvent(&event)
	}

	err = r.Finish()
	assert.Nil(t, err)

	s := r.(*sarifReporter)

	assert.Contains(t, *s.report.Runs[0].Results[0].Message.Markdown, "Licenses")
	assert.Contains(t, *s.report.Runs[0].Results[0].Message.Text, licenses[0])
	assert.Contains(t, *s.report.Runs[0].Results[1].Message.Markdown, sampleVulnSummary)
	assert.Contains(t, *s.report.Runs[0].Results[1].Message.Text, sampleVulnSummary)
	assert.Contains(t, *s.report.Runs[0].Results[2].Message.Markdown, "GitHub Project")
	assert.Contains(t, *s.report.Runs[0].Results[2].Message.Text, sampleProjectName)
}
