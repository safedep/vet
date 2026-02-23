package scanner

import (
	"context"
	"fmt"

	"github.com/safedep/vet/pkg/code"
	"github.com/safedep/vet/pkg/models"
)

type CodeAnalysisEnricherConfig struct {
	EnableDepsUsageEvidence bool
	EnableSignatureMatches  bool
}
type codeAnalysisEnricher struct {
	config           CodeAnalysisEnricherConfig
	ReaderRepository code.ReaderRepository
}

var _ PackageMetaEnricher = (*codeAnalysisEnricher)(nil)

func NewCodeAnalysisEnricher(config CodeAnalysisEnricherConfig, readerRepository code.ReaderRepository) *codeAnalysisEnricher {
	return &codeAnalysisEnricher{
		config:           config,
		ReaderRepository: readerRepository,
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

	if e.config.EnableSignatureMatches {
		if err := e.EnrichSignatureMatches(pkg); err != nil {
			return fmt.Errorf("failed to enrich signature matches: %w", err)
		}
	}

	return nil
}

func (e *codeAnalysisEnricher) Wait() error {
	return nil
}

func (e *codeAnalysisEnricher) EnrichDependencyUsageEvidence(pkg *models.Package) error {
	evidences, err := e.ReaderRepository.GetDependencyUsageEvidencesByPackageName(context.Background(), pkg.GetName())
	if err != nil {
		return fmt.Errorf("failed to fetch dependency usage evidence: %w", err)
	}

	pkg.CodeAnalysis.UsageEvidences = evidences
	return nil
}

func (e *codeAnalysisEnricher) EnrichSignatureMatches(pkg *models.Package) error {
	matches, err := e.ReaderRepository.GetSignatureMatchesByPackageHint(context.Background(), pkg.GetName())
	if err != nil {
		return fmt.Errorf("failed to fetch signature matches: %w", err)
	}

	pkg.CodeAnalysis.SignatureMatches = matches
	return nil
}
