package page

import (
	"strings"
	"testing"
	"unicode"

	"github.com/safedep/dry/tui/output"
	"github.com/safedep/dry/tui/stat"
	"github.com/safedep/dry/tui/theme"
	"github.com/stretchr/testify/assert"
)

// TestPageDrawsTheModeItIsGiven draws a report file while stderr is a rich
// terminal. The plain and agent pages give ASCII, with the icons of their
// mode.
func TestPageDrawsTheModeItIsGiven(t *testing.T) {
	output.SetMode(output.Rich)
	cases := []struct {
		mode output.Mode
		want []string
	}{
		{mode: output.Plain, want: []string{"Findings: 2", "[OK] No findings", "> 1 more", "[HIGH]"}},
		{mode: output.Agent, want: []string{"Findings: 2", "OK: No findings", "> 1 more", "[HIGH]"}},
	}
	for _, tc := range cases {
		t.Run(tc.mode.String(), func(t *testing.T) {
			p := For(tc.mode)
			got := []string{
				p.Cards(stat.Card{Label: "Findings", Value: "2"}),
				p.Success("No findings"),
				p.Hint("1 more"),
				p.Badge(theme.RoleHigh, "HIGH"),
				p.Heading("Tools"),
				p.Table().Headers("NAME").Row("vet").Render(),
			}
			text := strings.Join(got, "\n")
			for _, w := range tc.want {
				assert.Contains(t, text, w)
			}
			assert.Negative(t, strings.IndexFunc(text, func(r rune) bool { return r > unicode.MaxASCII }), text)
		})
	}
}
