// Package printer writes command data to stdout in the format of -o:
// table, plain, json or jsonl. It has the API that dry/tui/printer will
// have (decisions D15).
package printer

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/table"
)

// Format is a data format of -o.
type Format string

const (
	Table Format = "table"
	Plain Format = "plain"
	JSON  Format = "json"
	JSONL Format = "jsonl"
)

// Formats returns the formats of the printer.
func Formats() []Format { return []Format{Table, Plain, JSON, JSONL} }

// ParseFormat returns the format with a name.
func ParseFormat(s string) (Format, error) {
	for _, f := range Formats() {
		if string(f) == s {
			return f, nil
		}
	}
	return "", fmt.Errorf("unknown output format %q", s)
}

// DefaultFormat returns the format for a messaging mode: table when rich,
// plain when plain, and json for an agent.
func DefaultFormat(m output.Mode) Format {
	switch m {
	case output.Agent:
		return JSON
	case output.Plain:
		return Plain
	default:
		return Table
	}
}

// Rows is the tabular view of a value, for table and plain.
type Rows struct {
	Headers []string
	Rows    [][]string
	Title   string
	Footer  string
	// Empty replaces a table with no rows.
	Empty string
	// Columns tells the table how to fit each column to a narrow terminal.
	// Plain ignores it.
	Columns []table.Column
}

// Printer writes data in one format.
type Printer struct {
	w      io.Writer
	format Format
}

// Option changes a printer.
type Option func(*Printer)

// WithWriter replaces stdout.
func WithWriter(w io.Writer) Option { return func(p *Printer) { p.w = w } }

// New returns a printer that writes to stdout.
func New(f Format, opts ...Option) *Printer {
	p := &Printer{w: output.Stdout(), format: f}
	for _, o := range opts {
		o(p)
	}
	return p
}

// Format returns the format of the printer.
func (p *Printer) Format() Format { return p.format }

// Print writes value as json or jsonl, or rows as table or plain. For jsonl,
// a slice gives one line for each element.
func (p *Printer) Print(value any, rows Rows) error {
	switch p.format {
	case JSON:
		enc := json.NewEncoder(p.w)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		return enc.Encode(value)
	case JSONL:
		return p.jsonLines(value)
	case Plain:
		return p.plain(rows)
	default:
		r := table.New().Headers(rows.Headers...).Rows(rows.Rows...).Columns(rows.Columns...).
			Title(rows.Title).Footer(rows.Footer)
		if rows.Empty != "" {
			r.EmptyMessage(rows.Empty)
		}
		_, err := fmt.Fprintln(p.w, r.Render())
		return err
	}
}

// PrintText writes value as json or jsonl, or the lines as table or plain.
// It is for output that a person reads as text, not as a table: one value,
// one line, or a list.
func (p *Printer) PrintText(value any, lines ...string) error {
	if p.format == JSON || p.format == JSONL {
		return p.Print(value, Rows{})
	}
	for _, l := range lines {
		if _, err := fmt.Fprintln(p.w, l); err != nil {
			return err
		}
	}
	return nil
}

func (p *Printer) jsonLines(value any) error {
	enc := json.NewEncoder(p.w)
	enc.SetEscapeHTML(false)
	v := reflect.ValueOf(value)
	if v.Kind() != reflect.Slice && v.Kind() != reflect.Array {
		return enc.Encode(value)
	}
	for i := range v.Len() {
		if err := enc.Encode(v.Index(i).Interface()); err != nil {
			return err
		}
	}
	return nil
}

// plain writes one tab-separated line for the headers and for each row, for
// cut and awk. A tab or a line break in a cell becomes a space.
func (p *Printer) plain(rows Rows) error {
	var lines [][]string
	if len(rows.Headers) > 0 {
		lines = append(lines, rows.Headers)
	}
	lines = append(lines, rows.Rows...)
	for _, cells := range lines {
		clean := make([]string, len(cells))
		for i, c := range cells {
			clean[i] = plainCell.Replace(c)
		}
		if _, err := fmt.Fprintln(p.w, strings.Join(clean, "\t")); err != nil {
			return err
		}
	}
	return nil
}

var plainCell = strings.NewReplacer("\t", " ", "\r\n", " ", "\n", " ", "\r", " ")
