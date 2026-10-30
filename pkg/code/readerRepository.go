package code

import (
	"context"
	"fmt"

	"github.com/safedep/vet/ent"
	"github.com/safedep/vet/ent/codesignaturematch"
	"github.com/safedep/vet/ent/depsusageevidence"
)

type readerRepositoryImpl struct {
	client *ent.Client
}

var _ ReaderRepository = (*readerRepositoryImpl)(nil)

func NewReaderRepository(client *ent.Client) (ReaderRepository, error) {
	return &readerRepositoryImpl{
		client: client,
	}, nil
}

func (r *readerRepositoryImpl) GetDependencyUsageEvidencesByPackageName(ctx context.Context, packageName string) ([]*ent.DepsUsageEvidence, error) {
	evidences, err := r.client.DepsUsageEvidence.Query().
		Where(depsusageevidence.PackageHint(packageName)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch dependency usage evidence: %w", err)
	}
	return evidences, nil
}

// GetJavaDependencyUsageEvidences returns Java evidence from the selected code
// database. The caller is responsible for selecting the database for this scan.
func (r *readerRepositoryImpl) GetJavaDependencyUsageEvidences(ctx context.Context) ([]*ent.DepsUsageEvidence, error) {
	evidences, err := r.client.DepsUsageEvidence.Query().
		Where(depsusageevidence.UsageFilePathHasSuffix(".java")).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Java dependency usage evidence: %w", err)
	}
	return evidences, nil
}

func (r *readerRepositoryImpl) GetSignatureMatchesByPackageHint(ctx context.Context, packageHint string) ([]*ent.CodeSignatureMatch, error) {
	matches, err := r.client.CodeSignatureMatch.Query().
		Where(codesignaturematch.PackageHint(packageHint)).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch signature matches: %w", err)
	}
	return matches, nil
}

func (r *readerRepositoryImpl) GetAllSignatureMatches(ctx context.Context) ([]*ent.CodeSignatureMatch, error) {
	matches, err := r.client.CodeSignatureMatch.Query().All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch all signature matches: %w", err)
	}
	return matches, nil
}

func (r *readerRepositoryImpl) GetApplicationSignatureMatches(ctx context.Context) ([]*ent.CodeSignatureMatch, error) {
	matches, err := r.client.CodeSignatureMatch.Query().
		Where(codesignaturematch.PackageHintIsNil()).
		All(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch application signature matches: %w", err)
	}
	return matches, nil
}
