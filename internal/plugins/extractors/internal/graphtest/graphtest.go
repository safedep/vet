// Package graphtest holds the test options for the vet lockfile copies.
package graphtest

import (
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/binary/proto/metadata"
	"github.com/google/osv-scalibr/extractor"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/graph"
	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/lockmeta"
)

// IgnoreGraph leaves the package ids, the parent ids, the direct mark and
// the lockmeta URL and hash out of the upstream tests. Upstream does not set
// them. The golden test of the lockfile package checks the graph, and the
// vet tests check the URL and the hash.
var IgnoreGraph = cmp.Options{
	cmpopts.IgnoreFields(extractor.Package{}, "ID", "ParentIDs"),
	cmp.FilterValues(func(a, b metadata.Protoable) bool { return isWrapped(a) || isWrapped(b) },
		cmp.Transformer("unwrapDirect", unwrap)),
}

func isWrapped(m metadata.Protoable) bool {
	switch m.(type) {
	case *graph.Metadata, *lockmeta.Metadata:
		return true
	}
	return false
}

func unwrap(m metadata.Protoable) metadata.Protoable {
	for {
		switch w := m.(type) {
		case *graph.Metadata:
			m = w.Protoable
		case *lockmeta.Metadata:
			m = w.Protoable
		default:
			return m
		}
	}
}
