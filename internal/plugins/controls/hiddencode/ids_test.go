package hiddencode

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/plugins/internal/hiddencode"
)

// TestEachSignalHasAControl keeps the ids of the analysis and the control
// descriptions in step. Evaluate looks up the description of each signal.
func TestEachSignalHasAControl(t *testing.T) {
	var got []string
	for _, i := range infos {
		got = append(got, i.ID)
		assert.NotEmpty(t, remediation[i.ID], i.ID)
	}
	assert.ElementsMatch(t, hiddencode.IDs(), got)
}
