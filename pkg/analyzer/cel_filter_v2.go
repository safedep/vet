package analyzer

import (
	"fmt"
	"os"

	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/pkg/analyzer/filterv2"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
)

type celFilterV2Analyzer struct {
	evaluator   filterv2.Evaluator
	failOnMatch bool

	packages map[string]*models.Package
	stat     celFilterStat
}

func NewCelFilterV2Analyzer(fl string, failOnMatch bool) (Analyzer, error) {
	evaluator, err := filterv2.NewEvaluator("single-filter-v2", true)
	if err != nil {
		return nil, err
	}

	err = evaluator.AddRule(&policyv1.Rule{
		Name:  "filter-v2-query",
		Value: fl,
	})
	if err != nil {
		return nil, err
	}

	return &celFilterV2Analyzer{
		evaluator:   evaluator,
		failOnMatch: failOnMatch,
		packages:    make(map[string]*models.Package),
		stat:        celFilterStat{},
	}, nil
}

func (f *celFilterV2Analyzer) Name() string {
	return "CEL Filter V2 Analyzer"
}

func (f *celFilterV2Analyzer) Analyze(manifest *models.PackageManifest,
	handler AnalyzerEventHandler,
) error {
	logger.Infof("CEL v2 filtering manifest: %s", manifest.Path)
	f.stat.IncScannedManifest()

	err := readers.NewManifestModelReader(manifest).EnumPackages(func(pkg *models.Package) error {
		f.stat.IncEvaluatedPackage()

		// Check if we have insights v2 data
		if pkg.InsightsV2 == nil {
			logger.Warnf("Package %s/%s does not have insights v2 data required for policy evaluation",
				pkg.GetName(), pkg.GetVersion())
			return nil
		}

		evalResult, err := f.evaluator.EvalPackage(pkg)
		if err != nil {
			f.stat.IncError(err)
			logger.Errorf("Failed to evaluate CEL v2 for %s:%s : %v",
				pkg.GetName(), pkg.GetVersion(), err)
			return nil
		}

		if evalResult.Matched() {
			// Avoid duplicates added to the table
			if _, ok := f.packages[pkg.Id()]; ok {
				return nil
			}

			f.stat.IncMatchedPackage()
			f.packages[pkg.Id()] = pkg

			// Create a temporary filter from the rule for compatibility
			rule := evalResult.GetMatchedProgram().GetRule()
			tempFilter := &filtersuite.Filter{
				Name:  rule.GetName(),
				Value: rule.GetValue(),
			}

			if err := handler(&AnalyzerEvent{
				Source:   f.Name(),
				Type:     ET_FilterExpressionMatched,
				Manifest: manifest,
				Filter:   tempFilter,
				Package:  pkg,
				Message:  "policy-filter",
			}); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return err
	}

	return f.notifyCaller(manifest, handler)
}

func (f *celFilterV2Analyzer) Finish() error {
	if f.stat.EvaluatedPackages() == 0 {
		return nil
	}

	// Build table
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.SetStyle(table.StyleLight)

	t.AppendHeader(table.Row{"Package", "Version", "Ecosystem"})
	for _, pkg := range f.packages {
		t.AppendRow(table.Row{pkg.GetName(), pkg.GetVersion(), string(pkg.PackageDetails.Ecosystem)})
	}

	t.AppendFooter(table.Row{"Total", f.stat.EvaluatedPackages(), ""})
	t.AppendFooter(table.Row{"Matched", f.stat.MatchedPackages(), ""})
	t.AppendFooter(table.Row{"Unmatched", f.stat.EvaluatedPackages() - f.stat.MatchedPackages(), ""})

	if f.stat.MatchedPackages() > 0 {
		fmt.Printf("\nPackages matched by filter (using Policy Input schema):\n")
		t.Render()
	}

	return nil
}

func (f *celFilterV2Analyzer) notifyCaller(manifest *models.PackageManifest, handler AnalyzerEventHandler) error {
	if f.failOnMatch && f.stat.MatchedPackages() > 0 {
		if err := handler(&AnalyzerEvent{
			Source:   f.Name(),
			Type:     ET_AnalyzerFailOnError,
			Manifest: manifest,
			Message:  "policy-filter-fail-fast",
		}); err != nil {
			return err
		}
	}

	return nil
}
