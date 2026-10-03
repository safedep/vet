// Package style passes through dry/tui/style.
package style

import (
	"github.com/safedep/dry/tui/style"

	"github.com/safedep/vet/v2/internal/tui/theme"
)

// Info styles an information text.
func Info(s string) string { return style.Info(s) }

// Success styles a success text.
func Success(s string) string { return style.Success(s) }

// Warning styles a warning text.
func Warning(s string) string { return style.Warning(s) }

// Error styles an error text.
func Error(s string) string { return style.Error(s) }

// Faint styles a muted text.
func Faint(s string) string { return style.Faint(s) }

// Heading styles a heading.
func Heading(s string) string { return style.Heading(s) }

// Path styles a file path.
func Path(s string) string { return style.Path(s) }

// Badge styles a text as a badge in the colour of a role.
func Badge(r theme.Role, text string) string { return style.Badge(r, text) }
