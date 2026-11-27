package glyph

import (
	"strings"
	"testing"
	"unicode"

	"github.com/safedep/dry/tui/icon"
	"github.com/safedep/dry/tui/output"
	"github.com/safedep/dry/tui/theme"
	"github.com/stretchr/testify/assert"
)

// TestForMatchesTheModes keeps the step mark of vet the same as the arrow
// of dry/tui in each mode, and keeps each mark of the plain and agent modes
// ASCII.
func TestForMatchesTheModes(t *testing.T) {
	arrow, ok := theme.Default().Icons().Get(icon.KeyArrow)
	assert.True(t, ok)
	for _, m := range []output.Mode{output.Rich, output.Plain, output.Agent} {
		t.Run(m.String(), func(t *testing.T) {
			s := For(m)
			assert.Equal(t, arrow.Resolve(m), s.Step)
			if m == output.Rich {
				return
			}
			for _, mark := range []string{s.Sep, s.Ellipsis, s.Step} {
				assert.Negative(t, strings.IndexFunc(mark, func(r rune) bool { return r > unicode.MaxASCII }), "%q is not ASCII", mark)
			}
		})
	}
}
