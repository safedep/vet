// Package section passes through dry/tui/section.
package section

import "github.com/safedep/dry/tui/section"

// Titled puts a title over a body.
func Titled(title, body string) string { return section.Titled(title, body) }

// Hint styles a next-step hint.
func Hint(text string) string { return section.Hint(text) }

// Empty styles the text of an empty result.
func Empty(text string) string { return section.Empty(text) }

// Join joins the parts and skips the blank ones.
func Join(parts ...string) string { return section.Join(parts...) }
