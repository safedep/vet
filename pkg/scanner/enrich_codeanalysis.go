package scanner

import (
	"context"
	"fmt"

	"github.com/safedep/vet/pkg/code"
	"github.com/safedep/vet/pkg/models"
)

type CodeAnalysisEnricherConfig struct {
	ReaderRepository        code.ReaderRepository
	EnableDepsUsageEvidence bool
}
type codeAnalysisEnricher struct {
	config CodeAnalysisEnricherConfig
}

var _ PackageMetaEnricher = (*codeAnalysisEnricher)(nil)

func NewCodeAnalysisEnricher(config CodeAnalysisEnricherConfig) *codeAnalysisEnricher {
	return &codeAnalysisEnricher{
		config: config,
	}
}

func (e *codeAnalysisEnricher) Name() string {
	return "Code analysis Enricher"
}

// Fetch the dependency usage evidences for the given package and enrich the package with the evidences
func (e *codeAnalysisEnricher) Enrich(pkg *models.Package,
	_ PackageDependencyCallbackFn,
) error {
	pkg.CodeAnalysis = &models.CodeAnalysisResult{}

	if e.config.EnableDepsUsageEvidence {
		if err := e.EnrichDependencyUsageEvidence(pkg); err != nil {
			return fmt.Errorf("failed to enrich dependency usage evidence: %w", err)
		}
	}

	return nil
}

func (e *codeAnalysisEnricher) Wait() error {
	return nil
}

func (e *codeAnalysisEnricher) EnrichDependencyUsageEvidence(pkg *models.Package) error {
	evidences, err := e.config.ReaderRepository.GetDependencyUsageEvidencesByPackageName(context.Background(), pkg.GetName())
	if err != nil {
		return fmt.Errorf("failed to fetch dependency usage evidence: %w", err)
	}

	pkg.CodeAnalysis.UsageEvidences = evidences
	return nil
}
