package packagelockjson_test

import (
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
)

// ignoreGraph leaves the package ids and the parent ids out of the upstream
// tests. Upstream does not set them. The golden test of the adapter checks
// the graph.
var ignoreGraph = cmpopts.IgnoreFields(extractor.Package{}, "ID", "ParentIDs")
