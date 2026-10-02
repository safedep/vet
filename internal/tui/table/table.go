// Package table wraps dry/tui/table. It has the API that dry/tui/table will
// have (decisions D15).
package table

import (
	"github.com/charmbracelet/x/ansi"
	"github.com/safedep/dry/tui/output"
	"github.com/safedep/dry/tui/table"
)

// minColumn is the narrowest width that truncation gives a column.
const minColumn = 4

// Table is a fluent builder for styled tables. It truncates cells so that
// the table fits the terminal width.
type Table struct {
	t        *table.Table
	headers  []string
	rows     [][]string
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
// than the limit, Render shrinks the widest column first and ends each cut
// cell with "…".
func (t *Table) Render() string {
	limit := t.maxWidth
	if limit <= 0 {
		limit = output.Width()
	}
	widths := fit(columnWidths(t.headers, t.rows), limit)
	t.t.Headers(truncateRow(t.headers, widths)...)
	for _, r := range t.rows {
		t.t.Row(truncateRow(r, widths)...)
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

// fit shrinks the widest column, one cell at a time, until the table fits
// the limit or each column is at minColumn. Each column also takes two
// cells of padding and one cell of border, and the table one more border.
func fit(widths []int, limit int) []int {
	total := 1
	for _, w := range widths {
		total += w + 3
	}
	for total > limit {
		widest := -1
		for i, w := range widths {
			if w > minColumn && (widest < 0 || w > widths[widest]) {
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

func truncateRow(cells []string, widths []int) []string {
	out := make([]string, len(cells))
	for i, c := range cells {
		out[i] = c
		if i < len(widths) && ansi.StringWidth(c) > widths[i] {
			out[i] = ansi.Truncate(c, widths[i], "…")
		}
	}
	return out
}
