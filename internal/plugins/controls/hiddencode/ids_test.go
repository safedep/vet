package hiddencode

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/plugins/internal/hiddencode"
)

// TestEachSignalHasAControl keeps the ids of the analysis and the controls
// in step. Evaluate looks up the control of each signal.
func TestEachSignalHasAControl(t *testing.T) {
	var got []string
	for _, c := range controls {
		got = append(got, c.ID)
		assert.NotEmpty(t, c.remediation, c.ID)
	}
	assert.ElementsMatch(t, []string{
		hiddencode.IDPaddedCode, hiddencode.IDDisguisedScript, hiddencode.IDInvisibleUnicode,
		hiddencode.IDUnicodePayload, hiddencode.IDHistoryRewrite,
	}, got)
}
