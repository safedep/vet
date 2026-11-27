package table

import (
	"strings"
	"testing"
	"unicode"

	"github.com/charmbracelet/x/ansi"
	"github.com/safedep/dry/tui/output"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		name     string
		cell     string
		width    int
		fit      Fit
		lines    int
		ellipsis string
		want     string
	}{
		{name: "cut", cell: "abcdefghij", width: 5, fit: Cut, ellipsis: "…", want: "abcd…"},
		{name: "wrap to two lines", cell: "Malicious package", width: 10, fit: Wrap, lines: 2, ellipsis: "…", want: "Malicious\npackage"},
		{name: "wrap and cut at a word", cell: "Third-party action is not pinned to a commit", width: 12, fit: Wrap, lines: 2, ellipsis: "…", want: "Third-party\naction is…"},
		{name: "wrap and cut in ASCII", cell: "Third-party action is not pinned to a commit", width: 12, fit: Wrap, lines: 2, ellipsis: "...", want: "Third-party\naction is..."},
		{name: "cut in ASCII", cell: "abcdefghij", width: 5, fit: Cut, ellipsis: "...", want: "ab..."},
		{name: "cut left at a separator", cell: "/tmp/claude-0/uxreview/projects/npm-app", width: 20, fit: CutLeft, ellipsis: "…", want: "…/projects/npm-app"},
		{name: "cut left in ASCII", cell: "/tmp/claude-0/uxreview/projects/npm-app", width: 20, fit: CutLeft, ellipsis: "...", want: ".../projects/npm-app"},
		{name: "cut left with no separator", cell: "abcdefghij", width: 5, fit: CutLeft, ellipsis: "…", want: "…ghij"},
		{name: "wrap", cell: "one two three", width: 7, fit: Wrap, want: "one two\nthree"},
		{name: "keep", cell: "abcdefghij", width: 5, fit: Keep, want: "abcdefghij"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fitCell(tc.cell, tc.width, Column{Fit: tc.fit, Lines: tc.lines}, tc.ellipsis))
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
	assert.Contains(t, out, "...")
	assert.Contains(t, out, "high")

	short := New().Headers("A").Row("b").MaxWidth(50).Render()
	assert.NotContains(t, short, "...")
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
	assert.NotContains(t, out, "...")
	assert.Equal(t, 20, strings.Count(out, "word"))
}

func TestRenderMeasuresTheWidestLineOfACell(t *testing.T) {
	output.SetMode(output.Plain)
	t.Cleanup(func() { output.SetMode(output.Rich) })

	subject := "npm/evil-colors@1.4.1"
	out := New().Headers("SUBJECT", "FINDING").Row(subject, "Malicious\npackage").MaxWidth(40).Render()
	assert.Contains(t, out, subject, "a two-line cell is as wide as its widest line")
}

// TestRenderIsASCIIOutsideRichMode keeps the plain and agent modes ASCII
// while stderr is a rich terminal, as for a report file. Only the rich mode
// draws a box-drawing border and an ellipsis character.
func TestRenderIsASCIIOutsideRichMode(t *testing.T) {
	output.SetMode(output.Rich)
	long := strings.Repeat("very-long-package-name-", 5)
	cases := []struct {
		mode  output.Mode
		ascii bool
	}{
		{mode: output.Rich},
		{mode: output.Plain, ascii: true},
		{mode: output.Agent, ascii: true},
	}
	for _, tc := range cases {
		t.Run(tc.mode.String(), func(t *testing.T) {
			out := New().Mode(tc.mode).Headers("SEVERITY", "SUBJECT").Row("high", long).MaxWidth(40).Render()
			assert.Contains(t, out, "high")
			isASCII := strings.IndexFunc(out, func(r rune) bool { return r > unicode.MaxASCII }) < 0
			assert.Equal(t, tc.ascii, isASCII, out)
		})
	}
}

// TestPlainBorderKeepsTheCellText keeps untrusted text as it is. Only the
// border of a plain table is ASCII.
func TestPlainBorderKeepsTheCellText(t *testing.T) {
	out := New().Mode(output.Plain).Headers("TITLE").Row("├── payload").MaxWidth(40).Render()
	lines := strings.Split(out, "\n")
	require.Len(t, lines, 5)
	assert.Equal(t, "+-------------+", lines[0])
	assert.Equal(t, "| ├── payload |", lines[3])
}

func TestRenderCapsAColumnAtItsMax(t *testing.T) {
	out := New().Mode(output.Plain).Headers("NAME", "TAGS").Row(strings.Repeat("x", 30), "llm").
		Columns(Column{Max: 10}).MaxWidth(200).Render()
	assert.Contains(t, out, "| xxxxxxx... | llm  |")
}
