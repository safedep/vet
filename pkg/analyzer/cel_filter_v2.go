package analyzer

import (
	"fmt"
	"os"

	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/pkg/analyzer/filterv2"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
)

type celFilterV2Analyzer struct {
	evaluator   filterv2.Evaluator
	failOnMatch bool

	packages map[string]*celFilterV2MatchedPackage
	stat     celFilterStat
}

func NewCelFilterV2Analyzer(fl string, failOnMatch bool) (Analyzer, error) {
	evaluator, err := filterv2.NewEvaluator("single-filter-v2", filterv2.WithIgnoreError(true))
	if err != nil {
		return nil, fmt.Errorf("failed to create policy evaluator: %w", err)
	}

	policy := &policyv1.Policy{
		Version: policyv1.PolicyVersion_POLICY_VERSION_V2,
		Target:  policyv1.PolicyTarget_POLICY_TARGET_VET,
		Type:    policyv1.PolicyType_POLICY_TYPE_DENY,
		Name:    "filter-v2-policy",
		Rules: []*policyv1.Rule{
			{
				Name:  "filter-v2-rule",
				Value: fl,
			},
		},
	}

	err = evaluator.AddPolicy(policy)
	if err != nil {
		return nil, err
	}

	return &celFilterV2Analyzer{
		evaluator:   evaluator,
		failOnMatch: failOnMatch,
		packages:    make(map[string]*celFilterV2MatchedPackage),
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

		evalResult, err := f.evaluator.EvaluatePackage(pkg)
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

			prog, err := evalResult.GetMatchedProgram()
			if err != nil {
				logger.Warnf("failed to get matched program: %v", err)
				return nil
			}

			f.stat.IncMatchedPackage()
			f.packages[pkg.Id()] = newCelFilterV2MatchedPackage(pkg,
				prog.GetPolicy(), prog.GetRule())

			// Create a temporary filter from the rule for compatibility
			rule := prog.GetRule()
			tempFilter := &filtersuite.Filter{
				Name:  rule.GetName(),
				Value: rule.GetValue(),
			}

			if err := handler(&AnalyzerEvent{
				Source:         f.Name(),
				Type:           ET_FilterExpressionMatched,
				Manifest:       manifest,
				Filter:         tempFilter,
				FilterV2Policy: prog.GetPolicy(),
				FilterV2Rule:   prog.GetRule(),
				Package:        pkg,
				Message:        "policy-filter",
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
	pkgs := []*celFilterV2MatchedPackage{}
	for _, p := range f.packages {
		pkgs = append(pkgs, p)
	}

	data := newCelFilterMatchData(pkgs, f.stat)
	return data.renderTable(os.Stdout)
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
