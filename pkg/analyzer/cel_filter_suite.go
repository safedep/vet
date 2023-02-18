package analyzer

import (
	"os"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/pkg/analyzer/filter"
	"github.com/safedep/vet/pkg/models"
)

type celFilterSuiteAnalyzer struct {
	evaluator   filter.Evaluator
	suite       *filtersuite.FilterSuite
	failOnMatch bool
}

func NewCelFilterSuiteAnalyzer(path string, failOnMatch bool) (Analyzer, error) {
	fs, err := loadFilterSuiteFromFile(path)
	if err != nil {
		return nil, err
	}

	evaluator, err := filter.NewEvaluator(fs.GetName())
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
		evaluator:   evaluator,
		suite:       fs,
		failOnMatch: failOnMatch,
	}, nil
}

func (f *celFilterSuiteAnalyzer) Name() string {
	return "CEL Filter Suite"
}

func (f *celFilterSuiteAnalyzer) Analyze(manifest *models.PackageManifest,
	handler AnalyzerEventHandler) error {
	return nil
}

func (f *celFilterSuiteAnalyzer) Finish() error {
	return nil
}

// To correctly unmarshal a []byte into protobuf message, we must use
// protobuf SDK and not generic JSON / YAML decoder. Since there is no
// officially supported yamlpb, equivalent to jsonpb, we convert YAML
// to JSON before unmarshalling it into a protobuf message
func loadFilterSuiteFromFile(path string) (*filtersuite.FilterSuite, error) {
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
