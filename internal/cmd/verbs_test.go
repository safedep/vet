package cmd

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAllowedVerbsSorted(t *testing.T) {
	assert.True(t, slices.IsSorted(allowedVerbs), "keep allowedVerbs sorted")
	assert.Equal(t, len(allowedVerbs), len(slices.Compact(slices.Clone(allowedVerbs))), "allowedVerbs has a duplicate")
}

func TestIsAllowedVerb(t *testing.T) {
	cases := []struct {
		verb string
		want bool
	}{
		{"show", true},
		{"get", true},
		{"diff", true},
		{"validate", true},
		{"audit", true},
		{"scan", false},
		{"info", false},
		{"clean", false},
		{"unset", false},
		{"", false},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, IsAllowedVerb(tc.verb), tc.verb)
	}
}

// TestAllowedVerbs_devguideAlignment keeps the verb list of the guide and
// verbs.go the same.
func TestAllowedVerbs_devguideAlignment(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "DEVGUIDE.md"))
	require.NoError(t, err)
	guide := string(b)
	start := strings.Index(guide, "<!-- verbs:start -->")
	end := strings.Index(guide, "<!-- verbs:end -->")
	require.True(t, start >= 0 && end > start, "docs/DEVGUIDE.md has no verbs block")

	var verbs []string
	for _, f := range strings.FieldsFunc(guide[start:end], func(r rune) bool { return r == '`' }) {
		if f = strings.TrimSpace(f); f != "" && !strings.ContainsAny(f, ",<>!- \n") {
			verbs = append(verbs, f)
		}
	}
	assert.Equal(t, allowedVerbs, verbs)
}
