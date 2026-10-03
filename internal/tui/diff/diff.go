// Package diff passes through dry/tui/diff.
package diff

import "github.com/safedep/dry/tui/diff"

// Render returns a line diff of two texts.
func Render(oldText, newText string) string { return diff.Render(oldText, newText) }
