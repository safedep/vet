package code

import (
	"context"
	"fmt"

	"github.com/safedep/vet/ent"
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
