package analyzer

import (
	"io"
	"os"
	"time"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/gen/exceptionsapi"
	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/pkg/analyzer/filter"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
)

type exceptionsGenerator struct {
	writer          io.WriteCloser
	filterEvaluator filter.Evaluator
	expires         time.Time
	pkgCache        map[string]*models.Package
}

type ExceptionsGeneratorConfig struct {
	Path      string
	Filter    string
	ExpiresOn string
}

func NewExceptionsGenerator(config ExceptionsGeneratorConfig) (Analyzer, error) {
	fd, err := os.Create(config.Path)
	if err != nil {
		return nil, err
	}

	expiresOn, err := time.Parse("2006-01-02", config.ExpiresOn)
	if err != nil {
		return nil, err
	}

	filterEvaluator, err := filter.NewEvaluator("exceptions-generator", true)
	if err != nil {
		return nil, err
	}

	if utils.IsEmptyString(config.Filter) {
		config.Filter = "true"
	}

	err = filterEvaluator.AddFilter(&filtersuite.Filter{
		Name:  "exceptions-filter",
		Value: config.Filter,
	})
	if err != nil {
		return nil, err
	}

	logger.Infof("Initialized exceptions generator with filter: '%s' expiry: %s",
		config.Filter, expiresOn.Format(time.RFC3339))

	return &exceptionsGenerator{
		writer:          fd,
		filterEvaluator: filterEvaluator,
		expires:         expiresOn,
		pkgCache:        make(map[string]*models.Package),
	}, nil
}

func (f *exceptionsGenerator) Name() string {
	return "Exceptions Generator"
}

func (f *exceptionsGenerator) Analyze(manifest *models.PackageManifest,
	handler AnalyzerEventHandler) error {
	readers.NewManifestModelReader(manifest).EnumPackages(func(pkg *models.Package) error {
		res, err := f.filterEvaluator.EvalPackage(pkg)
		if err != nil {
			return err
		}

		if !res.Matched() {
			return nil
		}

		f.pkgCache[pkg.Id()] = pkg
		return nil
	})

	return nil
}

func (f *exceptionsGenerator) Finish() error {
	defer f.writer.Close()

	suite := exceptionsapi.ExceptionSuite{
		Name:        "Auto Generated Exceptions",
		Description: "Exceptions file auto-generated using vet",
		Exceptions:  make([]*exceptionsapi.Exception, 0),
	}

	for _, pkg := range f.pkgCache {
		logger.Infof("Adding %s to exceptions list", pkg.ShortName())

		suite.Exceptions = append(suite.Exceptions, &exceptionsapi.Exception{
			Id:        utils.NewUniqueId(),
			Ecosystem: string(pkg.Ecosystem),
			Name:      pkg.Name,
			Version:   pkg.Version,
			Expires:   f.expires.Format(time.RFC3339),
		})
	}

	err := utils.FromPbToYaml(f.writer, &suite)
	if err != nil {
		return err
	}

	return nil
}
