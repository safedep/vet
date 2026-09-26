package scanner

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/safedep/vet/ent"
	"github.com/safedep/vet/pkg/code"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/models"
)

type CodeAnalysisEnricherConfig struct {
	EnableDepsUsageEvidence bool
	EnableSignatureMatches  bool
}
type codeAnalysisEnricher struct {
	config           CodeAnalysisEnricherConfig
	ReaderRepository code.ReaderRepository
	javaEvidenceOnce sync.Once
	javaEvidences    []*ent.DepsUsageEvidence
	javaEvidenceErr  error
	javaArchiveCache sync.Map
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

	if !strings.EqualFold(string(pkg.Ecosystem), models.EcosystemMaven) {
		pkg.CodeAnalysis.UsageEvidences = evidences
		return nil
	}

	group, artifact, ok := strings.Cut(pkg.GetName(), ":")
	if !ok {
		pkg.CodeAnalysis.UsageEvidences = evidences
		return nil
	}
	archives := localJavaArchives(group, artifact, pkg.GetVersion())
	if len(archives) == 0 {
		pkg.CodeAnalysis.UsageEvidences = evidences
		return nil
	}

	e.javaEvidenceOnce.Do(func() {
		e.javaEvidences, e.javaEvidenceErr = e.ReaderRepository.GetJavaDependencyUsageEvidences(context.Background())
	})
	if e.javaEvidenceErr != nil {
		return e.javaEvidenceErr
	}
	if len(e.javaEvidences) == 0 {
		pkg.CodeAnalysis.UsageEvidences = evidences
		return nil
	}

	seen := make(map[int]struct{}, len(evidences))
	for _, evidence := range evidences {
		seen[evidence.ID] = struct{}{}
	}
	for _, archivePath := range archives {
		value, ok := e.javaArchiveCache.Load(archivePath)
		if !ok {
			index, err := indexJavaArchive(archivePath)
			if err != nil {
				logger.Warnf("skipping unreadable Java archive %s: %v", archivePath, err)
				continue
			}
			value, _ = e.javaArchiveCache.LoadOrStore(archivePath, index)
		}
		index := value.(*javaArchiveIndex)
		for _, evidence := range e.javaEvidences {
			if _, exists := seen[evidence.ID]; exists || !index.containsJavaImport(evidence) {
				continue
			}
			evidences = append(evidences, evidence)
			seen[evidence.ID] = struct{}{}
		}
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
