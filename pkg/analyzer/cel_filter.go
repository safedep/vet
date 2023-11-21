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
	"github.com/safedep/vet/pkg/readers"
)

type celFilterAnalyzer struct {
	evaluator   filter.Evaluator
	failOnMatch bool

	packages map[string]*models.Package
	stat     celFilterStat
}

func NewCelFilterAnalyzer(fl string, failOnMatch bool) (Analyzer, error) {
	evaluator, err := filter.NewEvaluator("single-filter", true)
	if err != nil {
		return nil, err
	}

	err = evaluator.AddFilter(&filtersuite.Filter{
		Name:  "filter-query",
		Value: fl,
	})
	if err != nil {
		return nil, err
	}

	return &celFilterAnalyzer{
		evaluator:   evaluator,
		failOnMatch: failOnMatch,
		packages:    make(map[string]*models.Package),
		stat:        celFilterStat{},
	}, nil
}

func (f *celFilterAnalyzer) Name() string {
	return "CEL Filter Analyzer"
}

func (f *celFilterAnalyzer) Analyze(manifest *models.PackageManifest,
	handler AnalyzerEventHandler) error {

	logger.Infof("CEL filtering manifest: %s", manifest.Path)
	f.stat.IncScannedManifest()

	readers.NewManifestModelReader(manifest).EnumPackages(func(pkg *models.Package) error {
		f.stat.IncEvaluatedPackage()

		res, err := f.evaluator.EvalPackage(pkg)
		if err != nil {
			f.stat.IncError(err)

			logger.Errorf("Failed to evaluate CEL for %s:%s : %v",
				pkg.PackageDetails.Name,
				pkg.PackageDetails.Version, err)

			return nil
		}

		if res.Matched() {
			// Avoid duplicates added to the table
			if _, ok := f.packages[pkg.Id()]; ok {
				return nil
			}

			f.stat.IncMatchedPackage()
			f.packages[pkg.Id()] = pkg

			handler(&AnalyzerEvent{
				Source:   f.Name(),
				Type:     ET_FilterExpressionMatched,
				Manifest: manifest,
				Filter:   res.GetMatchedProgram().GetFilter(),
				Package:  pkg,
				Message:  "cli-filter",
			})
		}

		return nil
	})

	return f.notifyCaller(manifest, handler)
}

func (f *celFilterAnalyzer) Finish() error {
	tbl := table.NewWriter()
	tbl.SetStyle(table.StyleLight)
	tbl.SetOutputMirror(os.Stdout)
	tbl.AppendHeader(table.Row{"Ecosystem", "Package", "Version",
		"Source"})

	for _, pkg := range f.packages {
		tbl.AppendRow(table.Row{pkg.PackageDetails.Ecosystem,
			pkg.PackageDetails.Name,
			pkg.PackageDetails.Version,
			f.pkgSource(pkg),
		})
	}

	f.stat.PrintStatMessage(os.Stderr)

	tbl.Render()
	return nil
}

func (f *celFilterAnalyzer) notifyCaller(manifest *models.PackageManifest,
	handler AnalyzerEventHandler) error {
	if f.failOnMatch && (len(f.packages) > 0) {
		handler(&AnalyzerEvent{
			Source:   f.Name(),
			Type:     ET_AnalyzerFailOnError,
			Manifest: manifest,
			Err: fmt.Errorf("failed due to filter match on %s",
				manifest.GetDisplayPath()),
		})
	}

	return nil
}

func (f *celFilterAnalyzer) pkgLatestVersion(pkg *models.Package) string {
	insight := utils.SafelyGetValue(pkg.Insights)
	return utils.SafelyGetValue(insight.PackageCurrentVersion)
}

func (f *celFilterAnalyzer) pkgSource(pkg *models.Package) string {
	insight := utils.SafelyGetValue(pkg.Insights)
	projects := utils.SafelyGetValue(insight.Projects)

	if len(projects) > 0 {
		return utils.SafelyGetValue(projects[0].Link)
	}

	return ""
}
