package reporter

import (
	"encoding/csv"
	"os"
	"strings"

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
	introducedBy    string
	pathToRoot      string
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

	records := []csvRecord{}
	for _, v := range r.violations {
		var msg string
		var ok bool

		if msg, ok = v.Message.(string); !ok {
			continue
		}

		introducedBy := ""
		pathToRoot := ""

		paths := v.Package.DependencyPath()
		pathPackages := []string{}

		for _, path := range paths {
			pathPackages = append(pathPackages, path.GetName())
		}

		if len(paths) > 0 {
			introducedBy = pathPackages[len(paths)-1]
			pathToRoot = strings.Join(pathPackages, " -> ")
		}

		records = append(records, csvRecord{
			ecosystem:       string(v.Package.Ecosystem),
			manifestPath:    v.Manifest.GetDisplayPath(),
			packageName:     v.Package.GetName(),
			packageVersion:  v.Package.GetVersion(),
			violationReason: msg,
			introducedBy:    introducedBy,
			pathToRoot:      pathToRoot,
		})
	}

	err := r.persistCsvRecords(records)
	if err != nil {
		return err
	}

	return nil
}

func (r *csvReporter) persistCsvRecords(records []csvRecord) error {
	f, err := os.Create(r.config.Path)
	if err != nil {
		return err
	}

	defer f.Close()

	w := csv.NewWriter(f)
	defer w.Flush()

	err = w.Write([]string{"Ecosystem",
		"Manifest Path",
		"Package Name",
		"Package Version",
		"Violation",
		"Introduced By",
		"Path To Root"})
	if err != nil {
		return err
	}

	for _, csvRecord := range records {
		if err := w.Write([]string{
			csvRecord.ecosystem, csvRecord.manifestPath,
			csvRecord.packageName, csvRecord.packageVersion,
			csvRecord.violationReason,
			csvRecord.introducedBy,
			csvRecord.pathToRoot,
		}); err != nil {
			return err
		}
	}

	return nil
}
