// Package table wraps dry/tui/table. It has the API that dry/tui/table will
// have (decisions D15).
package table

import (
	"strings"

	"github.com/charmbracelet/x/ansi"
	"github.com/safedep/dry/tui/output"
	"github.com/safedep/dry/tui/table"
)

// minColumn is the narrowest width that truncation gives a column.
const minColumn = 4

// Fit is how a cell fits a column that is narrower than the cell.
type Fit int

const (
	// Cut ends the cell with "…". It is the default.
	Cut Fit = iota
	// CutLeft starts the cell with "…" and keeps its end, for a path.
	CutLeft
	// Wrap breaks the cell into lines.
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
}

// Table is a fluent builder for styled tables. It fits the table to the
// terminal width: it drops the low-value columns, then shrinks the others.
type Table struct {
	t        *table.Table
	headers  []string
	rows     [][]string
	columns  []Column
	maxWidth int
}

// New returns an empty table.
func New() *Table { return &Table{t: table.New()} }

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
func (t *Table) Title(s string) *Table { t.t.Title(s); return t }

// Footer sets the line below the table.
func (t *Table) Footer(s string) *Table { t.t.Footer(s); return t }

// EmptyMessage sets the text that replaces a table with no rows.
func (t *Table) EmptyMessage(s string) *Table { t.t.EmptyMessage(s); return t }

// Render returns the table for the output mode. When the table is wider
// than the limit, Render drops columns in their Drop order, then shrinks
// the widest column that is not Keep, and fits each cell to its column.
func (t *Table) Render() string {
	limit := t.maxWidth
	if limit <= 0 {
		limit = output.Width()
	}
	widths := columnWidths(t.headers, t.rows)
	cols := make([]Column, len(widths))
	copy(cols, t.columns)
	keep := visible(widths, cols, limit)
	widths, cols = pick(widths, keep), pick(cols, keep)
	widths = fit(widths, cols, limit)
	t.t.Headers(fitRow(pick(t.headers, keep), widths, cols)...)
	for _, r := range t.rows {
		t.t.Row(fitRow(pick(r, keep), widths, cols)...)
	}
	return t.t.Render()
}

func columnWidths(headers []string, rows [][]string) []int {
	var w []int
	for _, r := range append([][]string{headers}, rows...) {
		for i, c := range r {
			if i >= len(w) {
				w = append(w, 0)
			}
			w[i] = max(w[i], ansi.StringWidth(c))
		}
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

func fitRow(cells []string, widths []int, cols []Column) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = c
		if i < len(widths) && ansi.StringWidth(c) > widths[i] {
			out[i] = fitCell(c, widths[i], cols[i].Fit)
		}
	}
	return out
}

func fitCell(s string, width int, f Fit) string {
	switch f {
	case Keep:
		return s
	case Wrap:
		return ansi.Wrap(s, width, "")
	case CutLeft:
		return cutLeft(s, width)
	default:
		return ansi.Truncate(s, width, "…")
	}
}

// cutLeft keeps the end of s in width cells. It starts the cut at a path
// separator when one is in the kept end, as in "…/projects/npm-app".
func cutLeft(s string, width int) string {
	tail := ansi.TruncateLeft(s, ansi.StringWidth(s)-width+1, "")
	if i := strings.IndexAny(tail, `/\`); i > 0 && i < len(tail)-1 {
		tail = tail[i:]
	}
	return "…" + tail
}
