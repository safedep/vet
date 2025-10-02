package analyzer

import (
	"os"

	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	"github.com/safedep/dry/api/pb"
	"github.com/safedep/vet/gen/filtersuite"
	"github.com/safedep/vet/pkg/analyzer/filterv2"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
	"github.com/safedep/vet/pkg/readers"
)

type celFilterSuiteV2Analyzer struct {
	evaluator   filterv2.Evaluator
	failOnMatch bool

	packages map[string]*celFilterV2MatchedPackage
	stat     celFilterStat
}

func NewCelFilterSuiteV2Analyzer(filePath string, failOnMatch bool) (Analyzer, error) {
	evaluator, err := filterv2.NewEvaluator("filter-suite-v2", filterv2.WithIgnoreError(true))
	if err != nil {
		return nil, err
	}

	policy, err := policyV2LoadPolicyFromFile(filePath)
	if err != nil {
		return nil, err
	}

	err = evaluator.AddPolicy(policy)
	if err != nil {
		return nil, err
	}

	return &celFilterSuiteV2Analyzer{
		evaluator:   evaluator,
		failOnMatch: failOnMatch,
		packages:    make(map[string]*celFilterV2MatchedPackage),
		stat:        celFilterStat{},
	}, nil
}

func (f *celFilterSuiteV2Analyzer) Name() string {
	return "CEL Filter Suite V2 Analyzer"
}

func (f *celFilterSuiteV2Analyzer) Analyze(manifest *models.PackageManifest,
	handler AnalyzerEventHandler,
) error {
	logger.Infof("CEL v2 policy suite filtering manifest: %s", manifest.Path)
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

			logger.Errorf("Failed to evaluate CEL v2 policy suite for %s:%s : %v",
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
				Package:        pkg,
				Message:        "policy-suite-filter",
				FilterV2Policy: prog.GetPolicy(),
				FilterV2Rule:   prog.GetRule(),
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

func (f *celFilterSuiteV2Analyzer) Finish() error {
	pkgs := []*celFilterV2MatchedPackage{}
	for _, p := range f.packages {
		pkgs = append(pkgs, p)
	}

	data := newCelFilterMatchData(pkgs, f.stat)
	return data.renderTable(os.Stdout)
}

func (f *celFilterSuiteV2Analyzer) notifyCaller(manifest *models.PackageManifest, handler AnalyzerEventHandler) error {
	if f.failOnMatch && f.stat.MatchedPackages() > 0 {
		if err := handler(&AnalyzerEvent{
			Source:   f.Name(),
			Type:     ET_AnalyzerFailOnError,
			Manifest: manifest,
			Message:  "policy-suite-filter-fail-fast",
		}); err != nil {
			return err
		}
	}

	return nil
}

// loadPolicyFromFile loads a policy from a file path
func policyV2LoadPolicyFromFile(filePath string) (*policyv1.Policy, error) {
	logger.Debugf("CEL Policy Suite: Loading policy from file: %s", filePath)

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = file.Close()
	}()

	var policy policyv1.Policy
	err = pb.FromYaml(file, &policy)
	if err != nil {
		return nil, err
	}

	return &policy, nil
}
