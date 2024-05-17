package reporter

import (
	"encoding/csv"
	"os"
	"strings"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/insightapi"
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
	osvId           string
	cveId           string
	vulnSeverity    string
	vulnSummary     string
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

		// Base record
		record := csvRecord{
			ecosystem:       string(v.Package.Ecosystem),
			manifestPath:    v.Manifest.GetDisplayPath(),
			packageName:     v.Package.GetName(),
			packageVersion:  v.Package.GetVersion(),
			violationReason: msg,
			introducedBy:    introducedBy,
			pathToRoot:      pathToRoot,
		}

		// Flatten the vulnerabilities
		insight := utils.SafelyGetValue(v.Package.Insights)
		vulnerabilities := utils.SafelyGetValue(insight.Vulnerabilities)

		// If no vulnerabilities, add the record as is and continue
		if len(vulnerabilities) == 0 {
			records = append(records, record)
			continue
		}

		for _, vuln := range vulnerabilities {
			vulnId := utils.SafelyGetValue(vuln.Id)
			aliases := utils.SafelyGetValue(vuln.Aliases)
			summary := utils.SafelyGetValue(vuln.Summary)

			cveId := ""
			for _, alias := range aliases {
				if strings.HasPrefix(alias, "CVE-") {
					cveId = alias
					break
				}
			}

			risk := ""
			severities := utils.SafelyGetValue(vuln.Severities)
			for _, severity := range severities {
				sevType := utils.SafelyGetValue(severity.Type)
				if sevType == insightapi.PackageVulnerabilitySeveritiesTypeCVSSV2 || sevType == insightapi.PackageVulnerabilitySeveritiesTypeCVSSV3 {
					risk = string(utils.SafelyGetValue(severity.Risk))
					break
				}
			}

			newRecord := record
			newRecord.osvId = vulnId
			newRecord.cveId = cveId
			newRecord.vulnSummary = summary
			newRecord.vulnSeverity = risk

			records = append(records, newRecord)
		}
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
		"Path To Root",
		"OSV ID",
		"CVE ID",
		"Vulnerability Severity",
		"Vulnerability Summary",
	})
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
			csvRecord.osvId,
			csvRecord.cveId,
			csvRecord.vulnSeverity,
			csvRecord.vulnSummary,
		}); err != nil {
			return err
		}
	}

	return nil
}
