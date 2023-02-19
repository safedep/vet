package analyzer

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/pkg/analyzer/filter"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

type celFilterMatchedPackage struct {
	pkg        *models.Package
	filterName string
}

type celFilterSuiteAnalyzer struct {
	evaluator       filter.Evaluator
	suite           *filtersuite.FilterSuite
	failOnMatch     bool
	matchedPackages map[string]*celFilterMatchedPackage
	stat            celFilterStat
}

func NewCelFilterSuiteAnalyzer(path string, failOnMatch bool) (Analyzer, error) {
	fs, err := loadFilterSuiteFromFile(path)
	if err != nil {
		return nil, err
	}

	evaluator, err := filter.NewEvaluator(fs.GetName(), true)
	if err != nil {
		return nil, err
	}

	for _, fl := range fs.GetFilters() {
		err = evaluator.AddFilter(fl.GetName(), fl.GetValue())
		if err != nil {
			return nil, err
		}
	}

	return &celFilterSuiteAnalyzer{
		evaluator:       evaluator,
		suite:           fs,
		failOnMatch:     failOnMatch,
		matchedPackages: make(map[string]*celFilterMatchedPackage),
		stat:            celFilterStat{},
	}, nil
}

func (f *celFilterSuiteAnalyzer) Name() string {
	return "CEL Filter Suite"
}

func (f *celFilterSuiteAnalyzer) Analyze(manifest *models.PackageManifest,
	handler AnalyzerEventHandler) error {

	logger.Infof("CEL Filter Suite: Analyzing manifest: %s", manifest.Path)

	f.stat.IncScannedManifest()
	for _, pkg := range manifest.Packages {
		f.stat.IncEvaluatedPackage()

		res, err := f.evaluator.EvalPackage(pkg)
		if err != nil {
			f.stat.IncError(err)

			logger.Errorf("Failed to evaluate CEL for %s:%s : %v",
				pkg.PackageDetails.Name,
				pkg.PackageDetails.Version, err)

			continue
		}

		if res.Matched() {
			f.queueMatchedPkg(pkg, res.GetMatchedFilter().Name())
		}
	}

	if f.failOnMatch && (len(f.matchedPackages) > 0) {
		handler(&AnalyzerEvent{
			Source:   f.Name(),
			Type:     ET_AnalyzerFailOnError,
			Manifest: manifest,
			Err:      fmt.Errorf("failed due to filter suite match on %s", manifest.Path),
		})
	}

	return nil
}

func (f *celFilterSuiteAnalyzer) Finish() error {
	f.renderMatchTable()
	return nil
}

func (f *celFilterSuiteAnalyzer) renderMatchTable() {
	tbl := table.NewWriter()
	tbl.SetStyle(table.StyleLight)
	tbl.SetOutputMirror(os.Stdout)
	tbl.AppendHeader(table.Row{"Ecosystem", "Package", "Latest",
		"Filter"})

	for _, mp := range f.matchedPackages {
		insights := utils.SafelyGetValue(mp.pkg.Insights)
		tbl.AppendRow(table.Row{
			mp.pkg.PackageDetails.Ecosystem,
			fmt.Sprintf("%s@%s", mp.pkg.PackageDetails.Name,
				mp.pkg.PackageDetails.Version),
			utils.SafelyGetValue(insights.PackageCurrentVersion),
			mp.filterName,
		})
	}

	f.stat.PrintStatMessage(os.Stderr)
	tbl.Render()
}

func (f *celFilterSuiteAnalyzer) queueMatchedPkg(pkg *models.Package,
	filterName string) {
	if _, ok := f.matchedPackages[pkg.Id()]; ok {
		return
	}

	f.stat.IncMatchedPackage()
	f.matchedPackages[pkg.Id()] = &celFilterMatchedPackage{
		filterName: filterName,
		pkg:        pkg,
	}
}

// To correctly unmarshal a []byte into protobuf message, we must use
// protobuf SDK and not generic JSON / YAML decoder. Since there is no
// officially supported yamlpb, equivalent to jsonpb, we convert YAML
// to JSON before unmarshalling it into a protobuf message
func loadFilterSuiteFromFile(path string) (*filtersuite.FilterSuite, error) {
	logger.Debugf("CEL Filter Suite: Loading suite from file: %s", path)

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	var msg filtersuite.FilterSuite
	err = utils.FromYamlToPb(file, &msg)
	if err != nil {
		return nil, err
	}

	return &msg, nil
}
