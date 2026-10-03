package report

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/printer"
)

func TestListRowsFitANarrowTerminal(t *testing.T) {
	t.Cleanup(func() {
		output.SetMode(output.Rich)
		output.SetWidthOverride(0)
	})
	output.SetMode(output.Plain)
	now := time.Now()
	entries := []*state.IndexEntry{{
		ID: "6f91914c2b7a4e0f9d1e", TargetKey: "/home/someone/work/clients/acme/projects/npm-app", Status: state.StatusCompleted,
		StartedAt: now.Add(-time.Hour), RunTime: 3 * time.Second, Packages: 6, Findings: 10, Gate: "NONE",
	}}
	_, rows := listRows(entries, now)

	cases := []struct {
		width   int
		want    []string
		notWant []string
	}{
		{width: 80, want: []string{"6f91914c ", "│ …/", "/projects/npm-app ", "FINDINGS"}, notWant: []string{"DURATION", "STATUS"}},
		{width: 140, want: []string{"6f91914c ", entries[0].TargetKey, "DURATION", "STATUS"}},
	}
	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.width), func(t *testing.T) {
			output.SetWidthOverride(tc.width)
			var buf bytes.Buffer
			require.NoError(t, printer.New(printer.Table, printer.WithWriter(&buf)).Print(nil, rows))
			for _, l := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
				assert.LessOrEqual(t, ansi.StringWidth(l), tc.width, l)
			}
			for _, s := range tc.want {
				assert.Contains(t, buf.String(), s)
			}
			for _, s := range tc.notWant {
				assert.NotContains(t, buf.String(), s)
			}
		})
	}

	var plain bytes.Buffer
	require.NoError(t, printer.New(printer.Plain, printer.WithWriter(&plain)).Print(nil, rows))
	assert.Contains(t, plain.String(), "DURATION\tSTATUS", "plain keeps every column")
	assert.Contains(t, plain.String(), entries[0].TargetKey)
}
