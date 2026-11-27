// Package glyph holds the marks that join, cut and start the lines of the
// terminal. Only the rich mode shows Unicode marks. The plain and agent
// modes get ASCII marks, because a CI log, a file or an agent reads them.
package glyph

import (
	"github.com/safedep/dry/tui/icon"
	"github.com/safedep/dry/tui/output"
	"github.com/safedep/dry/tui/theme"
)

// Set is the marks of one output mode.
type Set struct {
	// Sep joins two facts on one line.
	Sep string
	// Ellipsis ends a cut text.
	Ellipsis string
	// Step starts a step line and a progress line.
	Step string
}

var (
	rich  = Set{Sep: " · ", Ellipsis: "…"}
	ascii = Set{Sep: ", ", Ellipsis: "..."}
)

// For returns the marks of a mode. A new mode adds a set here, and the
// callers stay as they are. Step is the arrow of the dry icon set, so a
// step line of vet matches the step lines of dry/tui/steps.
func For(m output.Mode) Set {
	s := ascii
	if m == output.Rich {
		s = rich
	}
	if ic, ok := theme.Default().Icons().Get(icon.KeyArrow); ok {
		s.Step = ic.Resolve(m)
	}
	return s
}
