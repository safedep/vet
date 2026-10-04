package report

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

func TestCapabilityRows(t *testing.T) {
	caps := []*report.Capability{
		{ID: "openai.client", Product: "OpenAI SDK", Tags: []string{"ai", "llm"}, Change: model.ChangeAdded, Occurrences: []report.Occurrence{
			{File: "a.py", Line: 3, Callee: "openai//OpenAI"}, {File: "b.py", Line: 7, Callee: "openai//OpenAI"},
		}},
		{ID: "crypto.md5", Product: "MD5", Tags: []string{"cryptography", "weak"}},
	}
	cases := []struct {
		name    string
		delta   bool
		headers []string
		first   []string
	}{
		{"full scan", false, []string{"KIND", "CAPABILITY", "TAGS", "WHERE", "CALL"}, []string{"AI", "OpenAI SDK", "llm", "a.py:3", "openai//OpenAI"}},
		{"pull request", true, []string{"KIND", "CAPABILITY", "TAGS", "CHANGE", "WHERE", "CALL"}, []string{"AI", "OpenAI SDK", "llm", "added", "a.py:3", "openai//OpenAI"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows := capabilityRows(caps, tc.delta)
			assert.Equal(t, tc.headers, rows.Headers)
			require.Len(t, rows.Rows, 3, "one row for each call site, and one for a capability with none")
			assert.Equal(t, tc.first, rows.Rows[0])
			assert.Equal(t, "b.py:7", rows.Rows[1][len(tc.headers)-2])
			assert.Equal(t, "CRYPTO", rows.Rows[2][0])
		})
	}
}

func TestHasTagsKeepsCapabilitiesWithEveryTag(t *testing.T) {
	md5 := &report.Capability{Tags: []string{"cryptography", "hash", "weak"}}
	assert.True(t, hasTags(md5, nil))
	assert.True(t, hasTags(md5, []string{"cryptography", "weak"}))
	assert.False(t, hasTags(md5, []string{"ai"}))
}
