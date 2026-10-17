package evasion

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/controls"
	"github.com/safedep/vet/v2/internal/technique"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

// TestTechniqueRegistry is the gate of a detection contribution. Each
// attack control names a technique of the registry, and the corpus groups
// of each technique hold a case that it must catch and a near miss. A near
// miss is a case that gives no attack finding, so a hit of another
// technique is not one. internal/technique checks each entry on its own,
// and TestEvasionCorpus keeps each case that passes as a pass.
func TestTechniqueRegistry(t *testing.T) {
	catalog, err := controls.Catalog()
	require.NoError(t, err)
	var attacks []string
	for _, c := range catalog {
		if !c.Attack {
			assert.Empty(t, c.Technique, "%s: only an attack control names a technique", c.ID)
			continue
		}
		attacks = append(attacks, c.ID)
		_, ok := technique.Get(c.Technique)
		assert.True(t, ok, "%s: attack control names the technique %q, which the registry does not have", c.ID, c.Technique)
	}
	controlsOf := controls.TechniqueControls(catalog)

	cases := loadCases(t)
	for _, tc := range technique.All() {
		t.Run(tc.ID, func(t *testing.T) {
			assert.NotEmpty(t, controlsOf[tc.ID], "an attack control finds the technique")
			if tc.NoCorpus != "" {
				return
			}
			hits, nearMisses := 0, 0
			for _, group := range tc.Corpus {
				info, err := os.Stat(filepath.Join("cases", group))
				if assert.NoError(t, err, "corpus group %s", group) {
					assert.True(t, info.IsDir(), "corpus group %s", group)
				}
				for _, c := range cases {
					if c.group != group {
						continue
					}
					switch {
					case c.miss == "" && slices.ContainsFunc(c.want, func(id string) bool { return slices.Contains(controlsOf[tc.ID], id) }):
						hits++
					case !slices.ContainsFunc(c.want, func(id string) bool { return slices.Contains(attacks, id) }):
						nearMisses++
					}
				}
			}
			assert.Positive(t, hits, "the corpus groups hold a case that the technique must catch")
			assert.Positive(t, nearMisses, "the corpus groups hold a near miss that the technique must not catch")
		})
	}
}

// TestSampleReportAttackIsCurrent keeps the attack of the malware finding
// of the sample report equal to the registry. plugintest cannot import the
// registry, because it is public.
func TestSampleReportAttackIsCurrent(t *testing.T) {
	want, ok := technique.Get(technique.MaliciousPackage)
	require.True(t, ok)
	for _, f := range plugintest.SampleReport().FindingList {
		if f.ControlID == "malware" {
			assert.Equal(t, &finding.Attack{Technique: want.ID, MITRE: want.MITRE}, f.Attack)
			return
		}
	}
	assert.Fail(t, "the sample report has no malware finding")
}
