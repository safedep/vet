package technique

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

// mitreID is a MITRE ATT&CK technique or sub-technique id.
var mitreID = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

func TestGet(t *testing.T) {
	got, ok := Get(PaddedCode)
	assert.True(t, ok)
	assert.Equal(t, []string{"T1027", "T1564"}, got.MITRE)

	_, ok = Get("no-such-technique")
	assert.False(t, ok)
}

// TestRegistryEntries checks each entry on its own. test/evasion checks
// the entries against the control catalog and the corpus.
func TestRegistryEntries(t *testing.T) {
	seen := map[string]bool{}
	for _, tc := range All() {
		t.Run(tc.ID, func(t *testing.T) {
			assert.False(t, seen[tc.ID], "the technique id is unique")
			seen[tc.ID] = true
			assert.NotEmpty(t, tc.Name)
			if assert.NotEmpty(t, tc.MITRE, "the technique maps to MITRE ATT&CK") {
				for _, id := range tc.MITRE {
					assert.Regexp(t, mitreID, id)
				}
			}
			assert.NotEqual(t, len(tc.Corpus) == 0, tc.NoCorpus == "", "the technique has corpus groups or a reason in NoCorpus, not both")
		})
	}
}
