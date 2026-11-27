// Package page draws the parts of a page of data, such as the table
// format of a report, for the output mode of its destination. dry/tui
// draws for the messaging mode, which it detects from stderr. A report that
// goes to a file or a pipe needs ASCII while stderr is a rich terminal, so
// the caller gives the mode. Only the rich mode uses dry/tui, and only the
// rich mode draws Unicode and colour.
package page

import (
	"fmt"
	"strings"

	"github.com/safedep/dry/tui/icon"
	"github.com/safedep/dry/tui/output"
	"github.com/safedep/dry/tui/section"
	"github.com/safedep/dry/tui/stat"
	"github.com/safedep/dry/tui/style"
	"github.com/safedep/dry/tui/theme"

	"github.com/safedep/vet/v2/internal/tui/table"
)

// Page draws for one output mode.
type Page struct{ mode output.Mode }

// For returns the page of a mode. The rich mode needs the rich messaging
// mode.
func For(m output.Mode) Page { return Page{mode: m} }

// Table returns an empty table in the mode of the page.
func (p Page) Table() *table.Table { return table.New().Mode(p.mode) }

// Cards draws the count cards: boxes in rich mode, and one "label: value"
// line for each card in the other modes.
func (p Page) Cards(cards ...stat.Card) string {
	if p.mode == output.Rich {
		return stat.Render(cards...)
	}
	lines := make([]string, 0, len(cards))
	for _, c := range cards {
		lines = append(lines, fmt.Sprintf("%s: %s", c.Label, c.Value))
	}
	return strings.Join(lines, "\n")
}

// Heading draws a heading.
func (p Page) Heading(s string) string {
	if p.mode == output.Rich {
		return style.Heading(s)
	}
	return s
}

// Success draws a line with the success icon of the mode.
func (p Page) Success(s string) string {
	if p.mode == output.Rich {
		return style.Success(s)
	}
	return p.icon(icon.KeySuccess) + " " + s
}

// Hint draws a next-step hint with the arrow icon of the mode.
func (p Page) Hint(s string) string {
	if p.mode == output.Rich {
		return section.Hint(s)
	}
	return p.icon(icon.KeyArrow) + " " + s
}

// Badge draws a label, such as a severity: a coloured badge in rich mode,
// and "[LABEL]" in the other modes.
func (p Page) Badge(r theme.Role, s string) string {
	if p.mode == output.Rich {
		return style.Badge(r, s)
	}
	return "[" + s + "]"
}

func (p Page) icon(k icon.IconKey) string {
	ic, _ := theme.Default().Icons().Get(k)
	return ic.Resolve(p.mode)
}
