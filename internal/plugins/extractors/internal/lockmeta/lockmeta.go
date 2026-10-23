// Package lockmeta is the metadata of a lockfile entry that vet keeps
// beyond the scalibr metadata: the URL that the entry resolves from and
// its integrity hash. The lockfile control checks the URL, and pull request
// mode compares the hash with the base.
package lockmeta

import (
	"github.com/google/osv-scalibr/binary/proto/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"

	"github.com/safedep/vet/v2/model"
)

// Metadata wraps the scalibr metadata of an entry.
type Metadata struct {
	metadata.Protoable
	ResolvedURL   string
	IntegrityHash string
	// LocalSource marks an entry that the project builds from its own
	// tree: a workspace member, a path or an editable install.
	LocalSource bool
	// DeclaredAt is the field of a project file that sets the version of
	// the entry, or nil when the manifest declares it.
	DeclaredAt *model.Declaration
}

// Declared returns the field that sets the version of the entry, or nil.
func (m *Metadata) Declared() *model.Declaration { return m.DeclaredAt }

// Resolved returns the URL that the entry resolves from.
func (m *Metadata) Resolved() string { return m.ResolvedURL }

// Integrity returns the integrity hash of the entry.
func (m *Metadata) Integrity() string { return m.IntegrityHash }

// Local reports an entry that the project builds from its own tree.
func (m *Metadata) Local() bool { return m.LocalSource }

// DepGroups returns the dependency groups of the wrapped metadata.
func (m *Metadata) DepGroups() []string {
	if dg, ok := m.Protoable.(osv.DepGroups); ok {
		return dg.DepGroups()
	}
	return nil
}
