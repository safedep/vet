// Package graphtest holds the test options for the vet lockfile copies.
package graphtest

import (
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/binary/proto/metadata"
	"github.com/google/osv-scalibr/extractor"

	"github.com/safedep/vet/v2/internal/plugins/extractors/internal/graph"
)

// IgnoreGraph leaves the package ids, the parent ids and the direct mark
// out of the upstream tests. Upstream does not set them. The golden test of
// the lockfile package checks the graph.
var IgnoreGraph = cmp.Options{
	cmpopts.IgnoreFields(extractor.Package{}, "ID", "ParentIDs"),
	cmp.FilterValues(func(a, b metadata.Protoable) bool { return isWrapped(a) || isWrapped(b) },
		cmp.Transformer("unwrapDirect", unwrap)),
}

func isWrapped(m metadata.Protoable) bool {
	_, ok := m.(*graph.Metadata)
	return ok
}

func unwrap(m metadata.Protoable) metadata.Protoable {
	if w, ok := m.(*graph.Metadata); ok {
		return w.Protoable
	}
	return m
}
