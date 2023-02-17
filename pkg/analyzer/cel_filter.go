package analyzer

import (
	"fmt"
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/pkg/analyzer/filter"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

type celFilterAnalyzer struct {
	evaluator   filter.Evaluator
	failOnMatch bool

	packages map[string]*models.Package

	stat struct {
		manifests int
		packages  int
		matched   int
		err       int
	}
}

func NewCelFilterAnalyzer(fl string, failOnMatch bool) (Analyzer, error) {
	evaluator, err := filter.NewEvaluator("single-filter")
	if err != nil {
		return nil, err
	}

	err = evaluator.AddFilter("single-filter", fl)
	if err != nil {
		return nil, err
	}

	return &celFilterAnalyzer{
		evaluator:   evaluator,
		failOnMatch: failOnMatch,
		packages:    make(map[string]*models.Package),
	}, nil
}

func (f *celFilterAnalyzer) Name() string {
	return "CEL Filter Analyzer"
}

func (f *celFilterAnalyzer) Analyze(manifest *models.PackageManifest,
	handler AnalyzerEventHandler) error {

	logger.Infof("CEL filtering manifest: %s", manifest.Path)
	f.stat.manifests += 1

	for _, pkg := range manifest.Packages {
		f.stat.packages += 1

		res, err := f.evaluator.EvalPackage(pkg)
		if err != nil {
			f.stat.err += 1
			logger.Errorf("Failed to evaluate CEL for %s:%s : %v",
				pkg.PackageDetails.Name,
				pkg.PackageDetails.Version, err)
			continue
		}

		if res.Matched() {
			// Avoid duplicates added to the table
			if _, ok := f.packages[pkg.Id()]; ok {
				continue
			}

			f.stat.matched += 1
			f.packages[pkg.Id()] = pkg
		}
	}

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

	fmt.Printf("%s\n", text.Bold.Sprint("Filter evaluated with ",
		f.stat.matched, " out of ", f.stat.packages, " uniquely matched and ",
		f.stat.err, " error(s) ", "across ", f.stat.manifests,
		" manifest(s)"))

	tbl.Render()
	return nil
}

func (f *celFilterAnalyzer) notifyCaller(manifest *models.PackageManifest,
	handler AnalyzerEventHandler) error {
	if f.failOnMatch && (f.stat.matched > 0) {
		handler(&AnalyzerEvent{
			Source:   f.Name(),
			Type:     ET_AnalyzerFailOnError,
			Manifest: manifest,
			Err: fmt.Errorf("failed due to filter match on %s",
				manifest.Path),
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
