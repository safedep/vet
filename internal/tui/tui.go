// Package tui is the terminal boundary of vet. It is the only vet package
// tree that imports dry/tui, and it imports no vet package (decisions D15).
// The subpackages pass through the dry/tui parts that work today, and add
// the parts that dry/tui does not have yet in the shape that dry/tui will
// use: printer, table and escape.
package tui

import (
	drytui "github.com/safedep/dry/tui"
	"github.com/safedep/dry/tui/output"
	"github.com/safedep/dry/tui/theme"
)

// Theme is the design language of the output.
type Theme = theme.Theme

// Renderable is a view that renders for a theme and an output mode. A view
// does no I/O.
type Renderable interface {
	Render(t Theme, m output.Mode) string
}

// Info prints an information line on stderr.
func Info(format string, a ...any) { drytui.Info(format, a...) }

// Success prints a success line on stderr.
func Success(format string, a ...any) { drytui.Success(format, a...) }

// Warning prints a warning line on stderr.
func Warning(format string, a ...any) { drytui.Warning(format, a...) }

// Error prints an error line on stderr.
func Error(format string, a ...any) { drytui.Error(format, a...) }

// Faint prints a muted line on stderr in verbose mode.
func Faint(format string, a ...any) { drytui.Faint(format, a...) }

// Heading prints a heading on stderr.
func Heading(text string) { drytui.Heading(text) }

// Print renders a view on stdout.
func Print(r Renderable) { drytui.Print(r) }
