package bitbucket

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/checks"
	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/gen/insightapi"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/reporter"
	"github.com/stretchr/testify/assert"
)

func getBitbucketReporter(metaReportPath, annotationsReportPath string) (reporter.Reporter, error) {
	return NewBitBucketReporter(BitBucketReporterConfig{
		MetaReportPath:        metaReportPath,
		AnnotationsReportPath: annotationsReportPath,
		Tool: reporter.ToolMetadata{
			Name:       "vet",
			VendorName: "SafeDep",
		},
	})
}

func TestBitBucketReporter(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "bitbucket-reporter-test-*")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	metaReportPath := filepath.Join(tmpDir, "meta.json")
	annotationsReportPath := filepath.Join(tmpDir, "annotations.json")

	t.Run("NewBitBucketReporter", func(t *testing.T) {
		r, err := getBitbucketReporter(metaReportPath, annotationsReportPath)
		assert.NoError(t, err)
		assert.NotNil(t, r)
		assert.Equal(t, "BitBucket Code Insights Reporter", r.Name())
	})

	t.Run("Empty Report", func(t *testing.T) {
		r, err := getBitbucketReporter(metaReportPath, annotationsReportPath)
		assert.NoError(t, err)
		err = r.Finish()
		assert.NoError(t, err)

		// Verify meta report
		data, err := os.ReadFile(metaReportPath)
		assert.NoError(t, err)
		var metaReport CodeInsightsReport
		err = json.Unmarshal(data, &metaReport)
		assert.NoError(t, err)
		assert.Equal(t, "SafeDep Vet Scan", metaReport.Title)
		assert.Equal(t, "Scan summary from SafeDep vet", metaReport.Details)
		assert.Equal(t, "SafeDep/vet", metaReport.Reporter)
		assert.Equal(t, ReportResultPassed, metaReport.Result)
		assert.Empty(t, metaReport.Data)

		// Verify annotations report
		data, err = os.ReadFile(annotationsReportPath)
		assert.NoError(t, err)
		var annotationsReport []*CodeInsightsAnnotation
		err = json.Unmarshal(data, &annotationsReport)
		assert.NoError(t, err)
		assert.Empty(t, annotationsReport)
	})

	t.Run("Report with manifest", func(t *testing.T) {
		r, err := getBitbucketReporter(metaReportPath, annotationsReportPath)
		assert.NoError(t, err)

		pkg := &models.Package{
			PackageDetails: models.NewPackageDetail("npm", "test-package", "1.0.0"),
			Insights: &insightapi.PackageVersionInsight{
				Vulnerabilities: &[]insightapi.PackageVulnerability{
					{
						Id:      utils.PtrTo("CVE-2021-1234"),
						Summary: utils.PtrTo("A test vulnerability"),
					},
				},
			},
		}

		manifest := &models.PackageManifest{
			Packages: []*models.Package{pkg},
			Source: models.PackageManifestSource{
				Path: "pom.xml",
			},
		}

		pkg.Manifest = manifest

		r.AddManifest(manifest)
		err = r.Finish()
		assert.NoError(t, err)

		// Verify meta report
		data, err := os.ReadFile(metaReportPath)
		assert.NoError(t, err)
		var metaReport CodeInsightsReport
		err = json.Unmarshal(data, &metaReport)
		assert.NoError(t, err)
		assert.Equal(t, ReportResultFailed, metaReport.Result)
		assert.Len(t, metaReport.Data, 1)

		// Verify annotations report
		data, err = os.ReadFile(annotationsReportPath)
		assert.NoError(t, err)
		var annotationsReport []*CodeInsightsAnnotation
		err = json.Unmarshal(data, &annotationsReport)
		assert.NoError(t, err)
		assert.Len(t, annotationsReport, 1)
	})

	t.Run("Report with analyzer event", func(t *testing.T) {
		r, err := getBitbucketReporter(metaReportPath, annotationsReportPath)
		assert.NoError(t, err)

		event := &analyzer.AnalyzerEvent{
			Type: analyzer.ET_FilterExpressionMatched,
			Filter: &filtersuite.Filter{
				Name:      "test-filter",
				CheckType: checks.CheckType_CheckTypeLicense,
				Summary:   "A test filter",
			},
			Package: &models.Package{
				PackageDetails: models.NewPackageDetail("npm", "test-package", "1.0.0"),
				Manifest: &models.PackageManifest{
					Path: "pom.xml",
				},
			},
		}

		r.AddAnalyzerEvent(event)
		err = r.Finish()
		assert.NoError(t, err)

		// Verify meta report
		data, err := os.ReadFile(metaReportPath)
		assert.NoError(t, err)
		var metaReport CodeInsightsReport
		err = json.Unmarshal(data, &metaReport)
		assert.NoError(t, err)
		assert.Equal(t, ReportResultFailed, metaReport.Result)
		assert.Len(t, metaReport.Data, 1)

		// Verify annotations report
		data, err = os.ReadFile(annotationsReportPath)
		assert.NoError(t, err)
		var annotationsReport []*CodeInsightsAnnotation
		err = json.Unmarshal(data, &annotationsReport)
		assert.NoError(t, err)
		assert.Len(t, annotationsReport, 1)
	})
}
