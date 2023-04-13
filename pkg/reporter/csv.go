package reporter

import (
	"encoding/csv"
	"os"

	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
)

type CsvReportingConfig struct {
	Path string
}

type csvReporter struct {
	config     CsvReportingConfig
	csvRecords []csvRecord
	violations map[string]*analyzer.AnalyzerEvent
}

type csvRecord struct {
	ecosystem       string
	manifestPath    string
	packageName     string
	packageVersion  string
	violationReason string
}

func NewCsvReporter(config CsvReportingConfig) (Reporter, error) {
	return &csvReporter{
		config:     config,
		csvRecords: make([]csvRecord, 0),
		violations: make(map[string]*analyzer.AnalyzerEvent),
	}, nil
}

func (r *csvReporter) Name() string {
	return "CSV Report Generator"
}

func (r *csvReporter) AddManifest(manifest *models.PackageManifest) {}

func (r *csvReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {
	if !event.IsFilterMatch() {
		return
	}

	if event.Package == nil {
		return
	}

	if event.Package.Manifest == nil {
		return
	}

	pkgId := event.Package.Id()
	if _, ok := r.violations[pkgId]; ok {
		return
	}

	r.violations[pkgId] = event
}

func (r *csvReporter) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *csvReporter) Finish() error {
	logger.Infof("Generating consolidated CSV report: %s", r.config.Path)

	var ok bool

	violations := []csvRecord{}
	for _, v := range r.violations {
		var msg string
		if msg, ok = v.Message.(string); !ok {
			continue
		}

		violations = append(violations, csvRecord{
			ecosystem:       v.Manifest.Ecosystem,
			manifestPath:    v.Manifest.Path,
			packageName:     v.Package.Name,
			packageVersion:  v.Package.Version,
			violationReason: msg,
		})
	}

	csvResponse := r.generateCsv(violations)

	// Error case
	if csvResponse != nil {
		return csvResponse
	}
	return nil
}

func (r *csvReporter) generateCsv(csvRecords []csvRecord) error {

	records := []csvRecord{}

	f, err := os.Create(r.config.Path)
	defer f.Close()

	if err != nil {
		logger.Errorf("failed to open file : %v", err)
		return err
	}

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{"Ecosystem", "Manifest Path", "Package Name", "Package Version", "Violation Reason"})

	for _, csvRecord := range records {
		if err := w.Write([]string{csvRecord.ecosystem, csvRecord.manifestPath,
			csvRecord.packageName, csvRecord.packageVersion, csvRecord.violationReason}); err != nil {
			logger.Errorf("error writing record to file %v", err)
			return err
		}
	}

	return nil
}
