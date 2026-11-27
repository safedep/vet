// Package table wraps dry/tui/table. It has the API that dry/tui/table will
// have (decisions D15).
package table

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
	lgtable "github.com/charmbracelet/lipgloss/table"
	"github.com/charmbracelet/x/ansi"
	"github.com/safedep/dry/tui/table"

	"github.com/safedep/vet/v2/internal/tui/glyph"
	"github.com/safedep/vet/v2/internal/tui/output"
)

// minColumn is the narrowest width that truncation gives a column.
const minColumn = 4

// minWrap is the narrowest Wrap column with a line limit that wraps. A
// narrower column would break each word onto a line of its own.
const minWrap = 16

// Fit is how a cell fits a column that is narrower than the cell.
type Fit int

const (
	// Cut ends the cell with an ellipsis. It is the default.
	Cut Fit = iota
	// CutLeft starts the cell with an ellipsis and keeps its end, for a
	// path.
	CutLeft
	// Wrap breaks the cell into lines, at most Column.Lines when it is set.
	Wrap
	// Keep gives the column its full width. Render never cuts it.
	Keep
)

// Column tells Render how to fit a column into a narrow terminal.
type Column struct {
	Fit Fit
	// Drop is the order in which Render removes the column when the table
	// is too wide: 1 goes first. Zero keeps the column.
	Drop int
	// Max is the widest that the column gets, in cells. A wider cell fits
	// by Fit. Zero sets no limit.
	Max int
	// Lines is the most lines of a Wrap cell. The last line of a longer
	// cell ends with an ellipsis. A column narrower than minWrap cuts the
	// cell to one line instead. Zero sets no limit.
	Lines int
}

// Table is a fluent builder for styled tables. It fits the table to the
// terminal width: it drops the low-value columns, then shrinks the others.
type Table struct {
	mode     output.Mode
	headers  []string
	rows     [][]string
	columns  []Column
	maxWidth int
	title    string
	footer   string
	empty    string
}

// New returns an empty table in an output mode. A table on stderr takes the
// messaging mode. A table of data takes the data mode of its destination,
// so that a file or a pipe gets ASCII.
func New(m output.Mode) *Table { return &Table{mode: output.Drawable(m)} }

// Headers sets the header row.
func (t *Table) Headers(h ...string) *Table {
	t.headers = append([]string(nil), h...)
	return t
}

// Row appends one row.
func (t *Table) Row(cells ...string) *Table {
	t.rows = append(t.rows, append([]string(nil), cells...))
	return t
}

// Rows appends rows.
func (t *Table) Rows(rows ...[]string) *Table {
	for _, r := range rows {
		t.Row(r...)
	}
	return t
}

// Columns sets how each column fits, in the order of the headers. A
// column with no entry is Cut and never dropped.
func (t *Table) Columns(c ...Column) *Table {
	t.columns = append([]Column(nil), c...)
	return t
}

// MaxWidth sets the width that the table must fit. Zero, the default, uses
// the terminal width.
func (t *Table) MaxWidth(n int) *Table {
	t.maxWidth = n
	return t
}

// Title sets the line above the table.
func (t *Table) Title(s string) *Table { t.title = s; return t }

// Footer sets the line below the table.
func (t *Table) Footer(s string) *Table { t.footer = s; return t }

// EmptyMessage sets the text that replaces a table with no rows.
func (t *Table) EmptyMessage(s string) *Table { t.empty = s; return t }

// Render returns the table for the output mode. When the table is wider
// than the limit, Render drops columns in their Drop order, then shrinks
// the widest column that is not Keep, and fits each cell to its column.
func (t *Table) Render() string {
	ellipsis := glyph.For(t.mode).Ellipsis
	limit := t.maxWidth
	if limit <= 0 {
		limit = output.Width()
	}
	widths := columnWidths(t.headers, t.rows)
	cols := make([]Column, len(widths))
	copy(cols, t.columns)
	for i, c := range cols {
		if c.Max > 0 {
			widths[i] = min(widths[i], c.Max)
		}
	}
	keep := visible(widths, cols, limit)
	widths, cols = pick(widths, keep), pick(cols, keep)
	widths = fit(widths, cols, limit)
	headers := fitRow(pick(t.headers, keep), widths, cols, ellipsis)
	rows := make([][]string, 0, len(t.rows))
	for _, r := range t.rows {
		rows = append(rows, fitRow(pick(r, keep), widths, cols, ellipsis))
	}
	if t.mode == output.Rich {
		return t.rich(headers, rows)
	}
	return t.ascii(headers, rows)
}

// rich draws the table with dry/tui/table, which reads the messaging mode.
// The rich mode of a table needs the rich messaging mode.
func (t *Table) rich(headers []string, rows [][]string) string {
	return table.New().Headers(headers...).Rows(rows...).Title(t.title).Footer(t.footer).EmptyMessage(t.empty).Render()
}

// ascii draws the table of the plain and agent modes with no colour: an
// ASCII border in plain mode, and no border for an agent. dry/tui/table
// reads the messaging mode and draws its plain border with box-drawing
// characters, so a report file of a rich terminal cannot use it.
func (t *Table) ascii(headers []string, rows [][]string) string {
	var parts []string
	if t.title != "" {
		parts = append(parts, t.title)
	}
	switch {
	case len(rows) == 0 && t.empty != "":
		parts = append(parts, t.empty)
	default:
		border := lipgloss.ASCIIBorder()
		if t.mode == output.Agent {
			border = lipgloss.HiddenBorder()
		}
		pad := lipgloss.NewStyle().Padding(0, 1)
		parts = append(parts, lgtable.New().Headers(headers...).Rows(rows...).Border(border).
			StyleFunc(func(int, int) lipgloss.Style { return pad }).Render())
	}
	if t.footer != "" {
		parts = append(parts, t.footer)
	}
	return strings.Join(parts, "\n")
}

func columnWidths(headers []string, rows [][]string) []int {
	var w []int
	for _, r := range append([][]string{headers}, rows...) {
		for i, c := range r {
			if i >= len(w) {
				w = append(w, 0)
			}
			w[i] = max(w[i], cellWidth(c))
		}
	}
	return w
}

// cellWidth is the width of the widest line of a cell.
func cellWidth(c string) int {
	w := 0
	for l := range strings.SplitSeq(c, "\n") {
		w = max(w, ansi.StringWidth(l))
	}
	return w
}

// tableWidth is the width of a table with these column widths. Each column
// takes two cells of padding and one cell of border, and the table one
// more border.
func tableWidth(widths []int, keep []bool) int {
	total := 1
	for i, w := range widths {
		if keep == nil || keep[i] {
			total += w + 3
		}
	}
	return total
}

// visible returns the columns that stay. It drops the columns with the
// lowest Drop first, until the table fits the limit.
func visible(widths []int, cols []Column, limit int) []bool {
	keep := make([]bool, len(widths))
	for i := range keep {
		keep[i] = true
	}
	for tableWidth(widths, keep) > limit {
		next := -1
		for i, c := range cols {
			if keep[i] && c.Drop > 0 && (next < 0 || c.Drop < cols[next].Drop) {
				next = i
			}
		}
		if next < 0 {
			break
		}
		keep[next] = false
	}
	return keep
}

func pick[T any](s []T, keep []bool) []T {
	out := make([]T, 0, len(s))
	for i, v := range s {
		if i >= len(keep) || keep[i] {
			out = append(out, v)
		}
	}
	return out
}

// fit shrinks the widest column that is not Keep, one cell at a time,
// until the table fits the limit or each such column is at minColumn.
func fit(widths []int, cols []Column, limit int) []int {
	total := tableWidth(widths, nil)
	for total > limit {
		widest := -1
		for i, w := range widths {
			if w > minColumn && cols[i].Fit != Keep && (widest < 0 || w > widths[widest]) {
				widest = i
			}
		}
		if widest < 0 {
			break
		}
		widths[widest]--
		total--
	}
	return widths
}

func fitRow(cells []string, widths []int, cols []Column, ellipsis string) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = c
		if i < len(widths) && cellWidth(c) > widths[i] {
			out[i] = fitCell(c, widths[i], cols[i], ellipsis)
		}
	}
	return out
}

func fitCell(s string, width int, c Column, ellipsis string) string {
	switch c.Fit {
	case Keep:
		return s
	case Wrap:
		if c.Lines > 0 && width < minWrap {
			return ansi.Truncate(s, width, ellipsis)
		}
		return wrap(s, width, c.Lines, ellipsis)
	case CutLeft:
		return cutLeft(s, width, ellipsis)
	default:
		return ansi.Truncate(s, width, ellipsis)
	}
}

// wrap breaks s into lines of width cells at most. With n above zero, it
// keeps n lines, and the last line of a longer text ends with the
// ellipsis. ansi.Wrap can keep a hyphen past the width, so wrap cuts each
// line to the width.
func wrap(s string, width, n int, ellipsis string) string {
	lines := strings.Split(ansi.Wrap(s, width, ""), "\n")
	if n > 0 && len(lines) > n {
		lines = append(lines[:n-1], lastLine(strings.Join(lines[n-1:], " "), width, ellipsis))
	}
	for i, l := range lines {
		lines[i] = ansi.Truncate(l, width, "")
	}
	return strings.Join(lines, "\n")
}

// lastLine cuts s to one line of width cells that ends with the ellipsis.
// It cuts at a word when it can.
func lastLine(s string, width int, ellipsis string) string {
	room := width - ansi.StringWidth(ellipsis)
	if room <= 0 {
		return ansi.Truncate(s, width, "")
	}
	first, _, _ := strings.Cut(ansi.Wrap(s, room, ""), "\n")
	return ansi.Truncate(strings.TrimRight(first, " "), room, "") + ellipsis
}

// cutLeft keeps the end of s in width cells. It starts the cut at a path
// separator when one is in the kept end, as in ".../projects/npm-app".
func cutLeft(s string, width int, ellipsis string) string {
	tail := ansi.TruncateLeft(s, ansi.StringWidth(s)-width+ansi.StringWidth(ellipsis), "")
	if i := strings.IndexAny(tail, `/\`); i > 0 && i < len(tail)-1 {
		tail = tail[i:]
	}
	return ellipsis + tail
}
