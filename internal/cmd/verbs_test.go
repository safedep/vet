package cmd

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
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
