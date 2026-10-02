// Package table wraps dry/tui/table. It has the API that dry/tui/table will
// have (decisions D15).
package table

import "github.com/safedep/dry/tui/table"

// Table is a fluent builder for styled tables.
type Table struct {
	t *table.Table
}

// New returns an empty table.
func New() *Table { return &Table{t: table.New()} }

// Headers sets the header row.
func (t *Table) Headers(h ...string) *Table { t.t.Headers(h...); return t }

// Row appends one row.
func (t *Table) Row(cells ...string) *Table { t.t.Row(cells...); return t }

// Rows appends rows.
func (t *Table) Rows(rows ...[]string) *Table { t.t.Rows(rows...); return t }

// Title sets the line above the table.
func (t *Table) Title(s string) *Table { t.t.Title(s); return t }

// Footer sets the line below the table.
func (t *Table) Footer(s string) *Table { t.t.Footer(s); return t }

// EmptyMessage sets the text that replaces a table with no rows.
func (t *Table) EmptyMessage(s string) *Table { t.t.EmptyMessage(s); return t }

// Render returns the table for the output mode.
func (t *Table) Render() string { return t.t.Render() }
