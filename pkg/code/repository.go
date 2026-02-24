package code

import (
	"context"

	"github.com/safedep/code/plugin/depsusage"

	"github.com/safedep/vet/ent"
)

// SignatureMatchData holds the flattened data for a single signature match occurrence.
type SignatureMatchData struct {
	SignatureID          string
	SignatureVendor      string
	SignatureProduct     string
	SignatureService     string
	SignatureDescription string
	Tags                 []string
	FilePath             string
	Language             string
	Line                 uint
	Column               uint
	CalleeNamespace      string
	MatchedCall          string
	PackageHint          string // empty = app-level finding
}

// Currently we only need this in CodeScanner
type writerRepository interface {
	SaveDependencyUsage(context.Context, *depsusage.UsageEvidence) (*ent.DepsUsageEvidence, error)
	SaveSignatureMatch(context.Context, *SignatureMatchData) (*ent.CodeSignatureMatch, error)
}

// Repository exposed to rest of the vet to query code analysis data
// persisted in the storage. This is a contract to the rest of the system
type ReaderRepository interface {
	GetDependencyUsageEvidencesByPackageName(context.Context, string) ([]*ent.DepsUsageEvidence, error)
	GetSignatureMatchesByPackageHint(context.Context, string) ([]*ent.CodeSignatureMatch, error)
	GetAllSignatureMatches(context.Context) ([]*ent.CodeSignatureMatch, error)
	GetApplicationSignatureMatches(context.Context) ([]*ent.CodeSignatureMatch, error)
}
