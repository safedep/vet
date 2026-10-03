package table

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

func TestLimit(t *testing.T) {
	output.SetWidthOverride(120)
	t.Cleanup(func() { output.SetWidthOverride(0) })
	cases := []struct {
		name    string
		options plugin.MapConfig
		more    bool
	}{
		{name: "limit 1", options: plugin.MapConfig{"limit": 1}, more: true},
		{name: "all", options: plugin.MapConfig{"all": true, "limit": 1}},
		{name: "default", options: plugin.MapConfig(nil)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(tc.options)
			require.NoError(t, err)
			got := string(plugintest.TestSink(t, s, plugintest.SampleReport()))
			if tc.more {
				assert.Contains(t, got, "1 more (vet report show -o table --all)")
				assert.NotContains(t, got, "unpinned-action")
				return
			}
			assert.NotContains(t, got, "more (")
			assert.Contains(t, got, "unpinned-action")
		})
	}
	_, err := New(plugin.MapConfig{"limit": -1})
	assert.Error(t, err)
}

func TestCapabilities(t *testing.T) {
	output.SetWidthOverride(120)
	t.Cleanup(func() { output.SetWidthOverride(0) })
	cases := []struct {
		name    string
		options plugin.MapConfig
		noCaps  bool
		want    []string
		notWant []string
	}{
		{
			name: "default", options: nil,
			want: []string{"AI and crypto: 1 AI, 1 crypto", "OpenAI SDK Chat Completions", "src/chat.py:12", "MD5", "[WEAK]"},
		},
		{
			name: "limit 1 keeps AI first", options: plugin.MapConfig{"limit": 1},
			want:    []string{"OpenAI SDK", "1 more (vet report capability list)"},
			notWant: []string{"src/cache.py"},
		},
		{
			name: "no capabilities", noCaps: true,
			notWant: []string{"AI and crypto"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := New(tc.options)
			require.NoError(t, err)
			r := plugintest.SampleReport()
			if tc.noCaps {
				r.CapabilityList = nil
			}
			got := string(plugintest.TestSink(t, s, r))
			for _, w := range tc.want {
				assert.Contains(t, got, w)
			}
			for _, w := range tc.notWant {
				assert.NotContains(t, got, w)
			}
		})
	}
}

func TestCapabilityWhereCountsTheOtherCalls(t *testing.T) {
	c := &report.Capability{Occurrences: []report.Occurrence{{File: "a.py", Line: 3}, {File: "b.py", Line: 9}, {File: "c.py"}}}
	assert.Equal(t, "a.py:3 (+2)", CapabilityWhere(c))
	assert.Empty(t, CapabilityWhere(&report.Capability{}))
}
