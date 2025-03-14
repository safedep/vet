package reporter

import (
	"fmt"
	"os"

	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
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
	config  SarifReporterConfig
	builder *sarifBuilder
}

func NewSarifReporter(config SarifReporterConfig) (Reporter, error) {
	builder, err := newSarifBuilder(
		sarifBuilderToolMetadata{
			Name:    config.Tool.Name,
			Version: config.Tool.Version,
		},
	)
	if err != nil {
		return nil, err
	}

	return &sarifReporter{
		config:  config,
		builder: builder,
	}, nil
}

func (r *sarifReporter) Name() string {
	return "sarif"
}

func (r *sarifReporter) AddManifest(manifest *models.PackageManifest) {
	r.builder.AddManifest(manifest)
}

func (r *sarifReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	r.builder.AddAnalyzerEvent(event)
}

func (r *sarifReporter) AddPolicyEvent(event *policy.PolicyEvent) {
}

func (r *sarifReporter) Finish() error {
	logger.Infof("Writing SARIF report to %s", r.config.Path)

	fd, err := os.OpenFile(r.config.Path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}

	defer fd.Close()

	finalReport, err := r.builder.GetSarifReport()
	if err != nil {
		return fmt.Errorf("error getting SARIF report: %w", err)
	}

	return finalReport.Write(fd)
}
