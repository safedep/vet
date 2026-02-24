package code

import (
	"context"
	"fmt"

	"github.com/safedep/code/plugin/depsusage"

	"github.com/safedep/vet/ent"
	"github.com/safedep/vet/ent/codesourcefile"
)

func (r *writerRepositoryImpl) getOrCreateSourceFile(ctx context.Context, filePath string) (*ent.CodeSourceFile, error) {
	cf, err := r.client.CodeSourceFile.
		Query().
		Where(codesourcefile.Path(filePath)).
		Only(ctx)
	if err != nil {
		if ent.IsNotFound(err) {
			cf, err = r.client.CodeSourceFile.
				Create().
				SetPath(filePath).
				Save(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to create CodeSourceFile: %w", err)
			}
		} else {
			return nil, fmt.Errorf("failed to query CodeSourceFile: %w", err)
		}
	}
	return cf, nil
}

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
	cf, err := r.getOrCreateSourceFile(ctx, evidence.FilePath)
	if err != nil {
		return nil, err
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

func (r *writerRepositoryImpl) SaveSignatureMatch(ctx context.Context, data *SignatureMatchData) (*ent.CodeSignatureMatch, error) {
	cf, err := r.getOrCreateSourceFile(ctx, data.FilePath)
	if err != nil {
		return nil, err
	}

	creator := r.client.CodeSignatureMatch.
		Create().
		SetSignatureID(data.SignatureID).
		SetSignatureVendor(data.SignatureVendor).
		SetSignatureProduct(data.SignatureProduct).
		SetSignatureService(data.SignatureService).
		SetSignatureDescription(data.SignatureDescription).
		SetTags(data.Tags).
		SetFilePath(data.FilePath).
		SetLanguage(data.Language).
		SetLine(data.Line).
		SetColumn(data.Column).
		SetCalleeNamespace(data.CalleeNamespace).
		SetMatchedCall(data.MatchedCall).
		SetSourceFile(cf)

	if data.PackageHint != "" {
		creator.SetPackageHint(data.PackageHint)
	}

	saved, err := creator.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create CodeSignatureMatch: %w", err)
	}

	return saved, nil
}
