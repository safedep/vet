package code

import (
	"context"

	"github.com/safedep/code/plugin/depsusage"
	"github.com/safedep/vet/ent"
)

// Currently we only need this in CodeScanner
type writerRepository interface {
	SaveDependencyUsage(context.Context, *depsusage.UsageEvidence) error
}

// Repository exposed to rest of the vet to query code analysis data
// persisted in the storage. This is a contract to the rest of the system
type ReaderRepository interface {
	// Stuff like GetEvidenceByPackageName(...)
}

type writerRepositoryImpl struct {
	client *ent.Client
}

func newWriterRepository(client *ent.Client) (writerRepository, error) {
	return &writerRepositoryImpl{
		client: client,
	}, nil
}

func (r *writerRepositoryImpl) SaveDependencyUsage(ctx context.Context, evidence *depsusage.UsageEvidence) error {
	return nil
}
