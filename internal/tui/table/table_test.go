package table

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/safedep/dry/tui/output"
	"github.com/stretchr/testify/assert"
)

func TestFit(t *testing.T) {
	cases := []struct {
		name   string
		widths []int
		cols   []Column
		limit  int
		want   []int
	}{
		{name: "fits", widths: []int{5, 10}, limit: 80, want: []int{5, 10}},
		{name: "shrink widest", widths: []int{5, 40}, limit: 30, want: []int{5, 18}},
		{name: "shrink both", widths: []int{20, 20}, limit: 27, want: []int{10, 10}},
		{name: "stop at minimum", widths: []int{10, 10}, limit: 5, want: []int{minColumn, minColumn}},
		{name: "keep is never shrunk", widths: []int{30, 20}, cols: []Column{{Fit: Keep}}, limit: 40, want: []int{30, 4}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cols := make([]Column, len(tc.widths))
			copy(cols, tc.cols)
			assert.Equal(t, tc.want, fit(tc.widths, cols, tc.limit))
		})
	}
}

func TestVisible(t *testing.T) {
	cases := []struct {
		name  string
		cols  []Column
		limit int
		want  []bool
	}{
		{name: "fits", cols: []Column{{}, {Drop: 1}, {}}, limit: 80, want: []bool{true, true, true}},
		{name: "drop one", cols: []Column{{}, {Drop: 1}, {}}, limit: 25, want: []bool{true, false, true}},
		{name: "drop in order", cols: []Column{{Drop: 2}, {Drop: 1}, {}}, limit: 14, want: []bool{false, false, true}},
		{name: "nothing to drop", cols: []Column{{}, {}, {}}, limit: 10, want: []bool{true, true, true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, visible([]int{10, 10, 10}, tc.cols, tc.limit))
		})
	}
}

func TestFitCell(t *testing.T) {
	cases := []struct {
		name  string
		cell  string
		width int
		fit   Fit
		want  string
	}{
		{name: "cut", cell: "abcdefghij", width: 5, fit: Cut, want: "abcd…"},
		{name: "cut left at a separator", cell: "/tmp/claude-0/uxreview/projects/npm-app", width: 20, fit: CutLeft, want: "…/projects/npm-app"},
		{name: "cut left with no separator", cell: "abcdefghij", width: 5, fit: CutLeft, want: "…ghij"},
		{name: "wrap", cell: "one two three", width: 7, fit: Wrap, want: "one two\nthree"},
		{name: "keep", cell: "abcdefghij", width: 5, fit: Keep, want: "abcdefghij"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fitCell(tc.cell, tc.width, tc.fit))
		})
	}
}

func TestRenderTruncatesToWidth(t *testing.T) {
	output.SetMode(output.Plain)
	t.Cleanup(func() { output.SetMode(output.Rich) })

	long := "pkg:npm/" + strings.Repeat("very-long-package-name-", 5) + "@1.0.0"
	out := New().Headers("SEVERITY", "SUBJECT").Row("high", long).MaxWidth(50).Render()
	for _, line := range strings.Split(out, "\n") {
		assert.LessOrEqual(t, ansi.StringWidth(line), 50, line)
	}
	assert.Contains(t, out, "…")
	assert.Contains(t, out, "high")

	short := New().Headers("A").Row("b").MaxWidth(50).Render()
	assert.NotContains(t, short, "…")
}

func TestRenderFitsColumns(t *testing.T) {
	output.SetMode(output.Plain)
	t.Cleanup(func() { output.SetMode(output.Rich) })

	id := "dependency-confusion-internal"
	desc := strings.Repeat("word ", 20)
	out := New().Headers("ID", "PLUGIN", "TITLE").Row(id, "reputation", desc).
		Columns(Column{Fit: Keep}, Column{Drop: 1}, Column{Fit: Wrap}).MaxWidth(50).Render()
	for _, line := range strings.Split(out, "\n") {
		assert.LessOrEqual(t, ansi.StringWidth(line), 50, line)
	}
	assert.Contains(t, out, id)
	assert.NotContains(t, out, "PLUGIN")
	assert.NotContains(t, out, "…")
	assert.Equal(t, 20, strings.Count(out, "word"))
}

func TestRenderMeasuresTheWidestLineOfACell(t *testing.T) {
	output.SetMode(output.Plain)
	t.Cleanup(func() { output.SetMode(output.Rich) })

	subject := "npm/evil-colors@1.4.1"
	out := New().Headers("SUBJECT", "FINDING").Row(subject, "Malicious\npackage").MaxWidth(40).Render()
	assert.Contains(t, out, subject, "a two-line cell is as wide as its widest line")
}
