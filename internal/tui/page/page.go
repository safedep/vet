// Package page draws the parts of a page of data, such as the table
// format of a report, for the output mode of its destination. dry/tui
// draws for the messaging mode, which it detects from stderr. A report that
// goes to a file or a pipe needs ASCII while stderr is a rich terminal, so
// the caller gives the mode. Only the rich mode uses dry/tui, and only the
// rich mode draws Unicode and colour.
//
// Two changes to dry/tui would remove the plain drawing here: each part of
// dry/tui should take the mode from its caller, and the plain border of
// dry/tui/table should be lipgloss.ASCIIBorder.
package page

import (
	"fmt"
	"strings"

	"github.com/safedep/dry/tui/icon"
	"github.com/safedep/dry/tui/section"
	"github.com/safedep/dry/tui/stat"
	"github.com/safedep/dry/tui/style"
	"github.com/safedep/dry/tui/theme"

	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/table"
)

// Card is one count card: a short label and its value.
type Card = stat.Card

// Page draws for one output mode.
type Page struct{ mode output.Mode }

// For returns the page of a mode. A rich page needs the rich messaging
// mode, because dry/tui reads it. Under another messaging mode, For gives a
// plain page.
func For(m output.Mode) Page { return Page{mode: output.Drawable(m)} }

// Mode is the output mode of the page.
func (p Page) Mode() output.Mode { return p.mode }

// Table returns an empty table in the mode of the page.
func (p Page) Table() *table.Table { return table.New(p.mode) }

// Join puts a blank line between the parts that are not empty.
func Join(parts ...string) string { return section.Join(parts...) }

// Cards draws the count cards: boxes in rich mode, and one "label: value"
// line for each card in the other modes.
func (p Page) Cards(cards ...Card) string {
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

// Warning draws a line with the warning icon of the mode.
func (p Page) Warning(s string) string {
	if p.mode == output.Rich {
		return style.Warning(s)
	}
	return p.icon(icon.KeyWarning) + " " + s
}

// Error draws a line with the error icon of the mode.
func (p Page) Error(s string) string {
	if p.mode == output.Rich {
		return style.Error(s)
	}
	return p.icon(icon.KeyError) + " " + s
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
