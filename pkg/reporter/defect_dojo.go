package reporter

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
)

// DefectDojo accepts findings in SARIF report format. We'll use sarfBuilder
// to generate the SARIF report and post it to DefectDojo.

type DefectDojoProduct struct {
	ID            int       `json:"id"`
	FindingsCount int       `json:"findings_count"`
	FindingsList  []int     `json:"findings_list"`
	Tags          []string  `json:"tags"`
	Name          string    `json:"name"`
	Description   string    `json:"description"`
	Created       time.Time `json:"created"`
}

type DefectDojoToolMetadata struct {
	Name           string
	Version        string
	InformationURI string
}

type DefectDojoReporterConfig struct {
	Tool               DefectDojoToolMetadata
	IncludeVulns       bool
	IncludeMalware     bool
	ProductID          int
	EngagementName     string
	DefectDojoHostUrl  string
	DefectDojoApiV2Key string
}

type defectDojoReporter struct {
	config           DefectDojoReporterConfig
	builder          *sarifBuilder
	defectDojoClient *resty.Client
}

func NewDefectDojoReporter(config DefectDojoReporterConfig) (Reporter, error) {
	defectDojoClient := resty.New().
		SetHeader("Authorization", "Token "+config.DefectDojoApiV2Key).
		SetBaseURL(config.DefectDojoHostUrl)

	builder, err := newSarifBuilder(
		sarifBuilderConfig{
			Tool: sarifBuilderToolMetadata{
				Name:           config.Tool.Name,
				Version:        config.Tool.Version,
				InformationURI: config.Tool.InformationURI,
			},
			IncludeVulns:   config.IncludeVulns,
			IncludeMalware: config.IncludeMalware,
		},
	)
	if err != nil {
		return nil, err
	}

	return &defectDojoReporter{
		config:           config,
		builder:          builder,
		defectDojoClient: defectDojoClient,
	}, nil
}

func (r *defectDojoReporter) Name() string {
	return "defect-dojo"
}

func (r *defectDojoReporter) AddManifest(manifest *models.PackageManifest) {
	r.builder.AddManifest(manifest)
}

func (r *defectDojoReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	r.builder.AddAnalyzerEvent(event)
}

func (r *defectDojoReporter) AddPolicyEvent(event *policy.PolicyEvent) {
}

func (r *defectDojoReporter) Finish() error {
	tempSarifReportFile, err := os.CreateTemp("", "temp-sarif-*.json")
	if err != nil {
		return fmt.Errorf("error creating temporary file: %w", err)
	}
	defer os.Remove(tempSarifReportFile.Name()) // Clean up

	logger.Infof("Writing temporary SARIF report to %s", tempSarifReportFile.Name())

	fd, err := os.OpenFile(tempSarifReportFile.Name(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer fd.Close()

	finalReport, err := r.builder.GetSarifReport()
	if err != nil {
		return fmt.Errorf("error getting SARIF report: %w", err)
	}

	err = finalReport.Write(fd)
	if err != nil {
		return fmt.Errorf("error writing SARIF report: %w", err)
	}

	product := &DefectDojoProduct{}
	resp, err := r.defectDojoClient.R().
		SetResult(product).
		SetPathParams(map[string]string{
			"id": strconv.Itoa(r.config.ProductID),
		}).
		Get("/api/v2/products/{id}")
	if err != nil {
		return fmt.Errorf("couldn't get product information for product_id = %d: %w", r.config.ProductID, err)
	}
	if resp.IsError() {
		return fmt.Errorf("couldn't get product information for product_id = %d, response (%d) - %v", r.config.ProductID, resp.StatusCode(), resp.String())
	}

	dateStr := time.Now().Format("2006-01-02")

	resp, err = r.defectDojoClient.R().
		SetFile("file", tempSarifReportFile.Name()).
		SetFormData(map[string]string{
			"scan_date":              dateStr,
			"engagement_end_date":    dateStr,
			"active":                 "true",
			"tags":                   "vet",
			"apply_tags_to_findings": "true",
			"scan_type":              "SARIF",
			"auto_create_context":    "true",
			"product":                strconv.Itoa(r.config.ProductID),
			"product_name":           product.Name,
			"engagement_name":        r.config.EngagementName,
		}).
		Post("/api/v2/import-scan/")
	if err != nil {
		return fmt.Errorf("couldn't post scan report to DefectDojo: %w", err)
	}

	if resp.IsError() {
		return fmt.Errorf("couldn't post scan report to DefectDojo, response (%d) - %v", resp.StatusCode(), resp.String())
	}

	return nil
}
