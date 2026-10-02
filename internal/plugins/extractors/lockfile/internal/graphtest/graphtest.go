// Package graphtest holds the test options for the vet lockfile copies.
package graphtest

import (
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
)

// IgnoreGraph leaves the package ids and the parent ids out of the
// upstream tests. Upstream does not set them. The golden test of the
// lockfile package checks the graph.
var IgnoreGraph cmp.Option = cmpopts.IgnoreFields(extractor.Package{}, "ID", "ParentIDs")
