// Package lockmeta is the metadata of a lockfile entry that vet keeps
// beyond the scalibr metadata: the URL that the entry resolves from and
// its integrity hash. The lockfile control checks the URL, and pull request
// mode compares the hash with the base.
package lockmeta

import (
	"github.com/google/osv-scalibr/binary/proto/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
)

// Metadata wraps the scalibr metadata of an entry.
type Metadata struct {
	metadata.Protoable
	ResolvedURL   string
	IntegrityHash string
}

// Resolved returns the URL that the entry resolves from.
func (m *Metadata) Resolved() string { return m.ResolvedURL }

// Integrity returns the integrity hash of the entry.
func (m *Metadata) Integrity() string { return m.IntegrityHash }

// DepGroups returns the dependency groups of the wrapped metadata.
func (m *Metadata) DepGroups() []string {
	if dg, ok := m.Protoable.(osv.DepGroups); ok {
		return dg.DepGroups()
	}
	return nil
}
