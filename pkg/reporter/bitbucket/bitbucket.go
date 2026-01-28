package bitbucket

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/safedep/dry/utils"

	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/reporter"
)

type BitBucketReporterConfig struct {
	MetaReportPath        string
	AnnotationsReportPath string
	Tool                  reporter.ToolMetadata
}

type bitbucketReporter struct {
	config            BitBucketReporterConfig
	metaReport        *CodeInsightsReport
	annotationsReport []*CodeInsightsAnnotation
}

func NewBitBucketReporter(config BitBucketReporterConfig) (reporter.Reporter, error) {
	return &bitbucketReporter{
		config:            config,
		metaReport:        newBitBucketCodeInsightsReport(config.Tool),
		annotationsReport: make([]*CodeInsightsAnnotation, 0),
	}, nil
}

func (r *bitbucketReporter) Name() string {
	return "BitBucket Code Insights Reporter"
}

func (r *bitbucketReporter) AddManifest(manifest *models.PackageManifest) {
	r.metaReport.addManifest(manifest)

	for _, pkg := range manifest.Packages {
		r.annotationsReport = append(r.annotationsReport, newBitBucketAnnotationForPackage(pkg)...)
	}
}

func (r *bitbucketReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	if event.Package == nil || event.Filter == nil {
		return
	}

	r.metaReport.addAnalyzerEvent(event)
	r.annotationsReport = append(r.annotationsReport, newBitBucketAnnotationForAnalyzerEvent(event))
}

func (r *bitbucketReporter) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *bitbucketReporter) Finish() error {
	if err := r.writeReport(r.config.MetaReportPath, r.metaReport); err != nil {
		return err
	}

	if err := r.writeReport(r.config.AnnotationsReportPath, r.annotationsReport); err != nil {
		return err
	}

	return nil
}

func (r *bitbucketReporter) writeReport(path string, data any) error {
	if path == "" {
		// Skip if path is empty
		return nil
	}

	if utils.IsEmptyString(path) {
		return nil
	}

	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal BitBucket report: %w", err)
	}

	err = os.WriteFile(path, content, 0o644)
	if err != nil {
		return fmt.Errorf("failed to write BitBucket report: %w", err)
	}

	return nil
}
