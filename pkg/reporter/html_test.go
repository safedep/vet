package reporter

import (
	"testing"

	"github.com/google/osv-scanner/pkg/lockfile"
	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/pkg/models"
)

func TestHtmlReporterSkipsExcludedFromMalwareDetections(t *testing.T) {
	reporter, err := NewHtmlReporter(HtmlReportingConfig{
		Path: "/tmp/report.html",
	})
	assert.NoError(t, err)

	manifest := &models.PackageManifest{
		Source: models.PackageManifestSource{
			Type: models.ManifestSourceLocal,
			Path: "requirements.txt",
		},
		Path:      "/workspace/requirements.txt",
		Ecosystem: models.EcosystemPyPI,
		Packages: []*models.Package{
			{
				PackageDetails: lockfile.PackageDetails{
					Name:    "malicious-pkg",
					Version: "1.0.0",
				},
				MalwareAnalysis: &models.MalwareAnalysisResult{
					IsMalware: true,
				},
			},
			{
				PackageDetails: lockfile.PackageDetails{
					Name:    "suspicious-pkg",
					Version: "2.0.0",
				},
				MalwareAnalysis: &models.MalwareAnalysisResult{
					IsSuspicious: true,
				},
			},
			{
				PackageDetails: lockfile.PackageDetails{
					Name:    "excluded-pkg",
					Version: "3.0.0",
				},
				MalwareAnalysis: &models.MalwareAnalysisResult{
					Exclusion: &models.MalwareAnalysisExclusion{
						ExclusionID: "exc-1",
						Reason:      "tenant-approved investigation",
					},
				},
			},
		},
	}

	for _, pkg := range manifest.Packages {
		pkg.Manifest = manifest
	}

	reporter.AddManifest(manifest)

	htmlReporter := reporter.(*htmlReporter)
	detections := htmlReporter.getMalwareDetections()

	assert.Len(t, detections, 2)
	assert.Equal(t, "malicious-pkg", detections[0].Package)
	assert.Equal(t, "suspicious-pkg", detections[1].Package)
}
