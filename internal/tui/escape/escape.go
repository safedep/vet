// Package escape makes untrusted text safe to show on a terminal. Package
// names, file paths and workflow strings come from scanned repositories,
// and they can hold escape sequences that move the cursor, change the
// title or hide text. It has the API that dry/tui/escape will have
// (decisions D15).
package escape

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Line returns s as one line. Invalid UTF-8 becomes U+FFFD. It shows each control character, line breaks
// and tabs included, and each bidirectional format character as an escape,
// for example \n, \x1b or ‮.
func Line(s string) string {
	return escape(s, false)
}

// Text returns s with its line breaks kept. It escapes every other control
// character and each bidirectional format character.
func Text(s string) string {
	return escape(s, true)
}

func escape(s string, keepNewlines bool) string {
	if isSafe(s, keepNewlines) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch {
		case r == '\n' && keepNewlines:
			b.WriteRune(r)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == unicode.ReplacementChar:
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case unsafeRune(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isSafe(s string, keepNewlines bool) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == '\n' && keepNewlines {
			continue
		}
		if r < 0x20 || r == 0x7f || unsafeRune(r) {
			return false
		}
	}
	return true
}

// unsafeRune reports a C1 control character or a bidirectional format
// character. A bidirectional override can show text in another order than
// the bytes, as in the "Trojan Source" attack.
func unsafeRune(r rune) bool {
	switch {
	case r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	}
	return false
}
