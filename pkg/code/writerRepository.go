package code

import (
	"context"
	"fmt"

	"github.com/safedep/code/plugin/depsusage"
	"github.com/safedep/vet/ent"
	"github.com/safedep/vet/ent/codesourcefile"
)

type writerRepositoryImpl struct {
	client *ent.Client
}

var _ writerRepository = (*writerRepositoryImpl)(nil)

func newWriterRepository(client *ent.Client) (writerRepository, error) {
	return &writerRepositoryImpl{
		client: client,
	}, nil
}

func (r *writerRepositoryImpl) SaveDependencyUsage(ctx context.Context, evidence *depsusage.UsageEvidence) (*ent.DepsUsageEvidence, error) {
	// Get CodeSourceFile consisting this evidence, create new if it doesn't exist
	cf, err := r.client.CodeSourceFile.
		Query().
		Where(codesourcefile.Path(evidence.FilePath)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			cf, err = r.client.CodeSourceFile.
				Create().
				SetPath(evidence.FilePath).
				Save(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to create CodeSourceFile: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to query CodeSourceFile: %w", err)
		}
	}

	savedDepsUsageEvidence, err := r.client.DepsUsageEvidence.
		Create().
		SetPackageHint(evidence.PackageHint).
		SetModuleName(evidence.ModuleName).
		SetModuleItem(evidence.ModuleItem).
		SetModuleAlias(evidence.ModuleAlias).
		SetIsWildCardUsage(evidence.IsWildCardUsage).
		SetIdentifier(evidence.Identifier).
		SetUsageFilePath(evidence.FilePath).
		SetLine(evidence.Line).
		SetUsedIn(cf).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create UsageEvidence: %w", err)
	}

	return savedDepsUsageEvidence, nil
}
