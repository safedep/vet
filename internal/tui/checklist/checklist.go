// Package checklist renders the results of checks as a list: one line for
// each check with an icon for its status, and a fix line under a check that
// did not pass.
package checklist

import (
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/page"
)

// Status is the result of one check.
type Status int

const (
	Pass Status = iota
	Warn
	Fail
)

// Item is one check.
type Item struct {
	Status Status
	Name   string
	Text   string
	// Fix is the action that repairs a check that did not pass.
	Fix string
}

// minText is the narrowest text column that Lines wraps to.
const minText = 20

// Lines returns the list in an output mode. A list on stdout takes the
// mode of the printer, so a file or a pipe gets ASCII. The names start in
// one column, and the texts in another. In the rich mode, Lines wraps a
// long text to the terminal width.
func Lines(m output.Mode, items []Item) []string {
	p := page.For(m)
	icons := make([]string, len(items))
	iconWidth, nameWidth := 0, 0
	for i, it := range items {
		icons[i] = icon(p, it.Status)
		iconWidth = max(iconWidth, ansi.StringWidth(icons[i]))
		nameWidth = max(nameWidth, ansi.StringWidth(it.Name))
	}
	indent := iconWidth + nameWidth + 2
	width := 0
	if p.Mode() == output.Rich {
		width = output.Width() - indent
	}
	pad := strings.Repeat(" ", indent)
	var out []string
	for i, it := range items {
		text := it.Text
		if width >= minText {
			text = strings.ReplaceAll(ansi.Wrap(text, width, ""), "\n", "\n"+pad)
		}
		head := icons[i] + strings.Repeat(" ", iconWidth-ansi.StringWidth(icons[i])) + it.Name
		out = append(out, head+strings.Repeat(" ", indent-ansi.StringWidth(head))+text)
		if it.Status != Pass && it.Fix != "" {
			out = append(out, pad+p.Hint(it.Fix))
		}
	}
	return out
}

// icon returns the icon of a status and a space, in the colour of the
// status.
func icon(p page.Page, s Status) string {
	switch s {
	case Fail:
		return p.Error("")
	case Warn:
		return p.Warning("")
	default:
		return p.Success("")
	}
}
