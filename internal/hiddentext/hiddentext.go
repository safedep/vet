// Package hiddentext writes the invisible text of the hidden-code
// tests and of the evasion corpus.
package hiddentext

import "strings"

// Selectors hides text in variation selectors, one byte in each, as
// GlassWorm does.
func Selectors(text string) string {
	var b strings.Builder
	for _, c := range []byte(text) {
		if c < 16 {
			b.WriteRune(0xFE00 + rune(c))
		} else {
			b.WriteRune(0xE0100 + rune(c) - 16)
		}
	}
	return b.String()
}

// Tags spells ASCII text in Unicode tag characters.
func Tags(text string) string {
	var b strings.Builder
	for _, c := range text {
		b.WriteRune(0xE0000 + c)
	}
	return b.String()
}
