package finding

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCompare(t *testing.T) {
	fs := []*Finding{
		{ID: "f-2", ControlID: "b", Severity: SeverityLow},
		{ID: "f-3", ControlID: "a", Severity: SeverityLow},
		{ID: "f-1", ControlID: "a", Severity: SeverityLow},
		{ID: "f-9", ControlID: "z", Severity: SeverityCritical},
	}
	slices.SortFunc(fs, Compare)
	var ids []string
	for _, f := range fs {
		ids = append(ids, f.ID)
	}
	assert.Equal(t, []string{"f-9", "f-1", "f-3", "f-2"}, ids)
}
