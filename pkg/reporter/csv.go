package reporter

import (
	"encoding/csv"
	"fmt"
	"os"

	"github.com/safedep/vet/pkg/analyzer"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/policy"
	"github.com/safedep/vet/pkg/readers"
)

type csvReporter struct {
	csvRecords []CsvRecord
}

func NewCsvReporter() (Reporter, error) {
	return &csvReporter{}, nil
}

func (r *csvReporter) Name() string {
	return "Csv Report Generator"
}

func (r *csvReporter) AddManifest(manifest *models.PackageManifest) {
	r.csvRecords = make([]CsvRecord,0)
	readers.NewManifestModelReader(manifest).EnumPackages(func(pkg *models.Package) error {
		r.csvRecords = append(r.csvRecords,r.createCsvRecord(pkg))
		return nil
	})
}

func (r *csvReporter) AddAnalyzerEvent(event *analyzer.AnalyzerEvent) {}

func (r *csvReporter) AddPolicyEvent(event *policy.PolicyEvent) {}

func (r *csvReporter) Finish() error {

	csvResponse := r.generateCsv(r.csvRecords)

	// Error case
	if(csvResponse != nil){
		return csvResponse
	}
	return nil
}

type CsvRecord struct {
	packageName string
	updateTo    string
}

func (r *csvReporter) createCsvRecord(pkg *models.Package) *CsvRecord {
	return &CsvRecord{
		packageName: r.packageNameForRemediationAdvice(pkg),
		updateTo: 			utils.SafelyGetValue(insight.PackageCurrentVersion),		,
	}
}

func (r *csvReporter) generateCsv(csvRecords []CsvRecord) error{
	
	records := []CsvRecord{}

	f, err := os.Create("report.csv")
	defer f.Close()

	if err != nil {
		logger.Errorf("failed to open file : %v", err)
		return err
	}

	w := csv.NewWriter(f)
	defer w.Flush()

	w.Write([]string{"Package", "Update To"})

	for _, csvRecord := range records {
		if err := w.Write([]string{csvRecord.packageName, csvRecord.updateTo}); err != nil {
			logger.Errorf("error writing record to file %v", err)
			return err
		}
	}

	return nil
}

func (r *csvReporter) packageNameForRemediationAdvice(pkg *models.Package) string {
	return fmt.Sprintf("%s@%s", pkg.PackageDetails.Name,
		pkg.PackageDetails.Version)
}
