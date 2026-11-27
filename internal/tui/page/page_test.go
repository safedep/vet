package page

import (
	"strings"
	"testing"
	"unicode"

	"github.com/safedep/dry/tui/theme"
	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/tui/output"
)

// TestPageDrawsTheModeItIsGiven draws a report file while stderr is a rich
// terminal. The plain and agent pages give ASCII, with the icons of their
// mode.
func TestPageDrawsTheModeItIsGiven(t *testing.T) {
	prev := output.CurrentMode()
	t.Cleanup(func() { output.SetMode(prev) })
	output.SetMode(output.Rich)
	cases := []struct {
		mode output.Mode
		want []string
	}{
		{mode: output.Plain, want: []string{"Findings: 2", "[OK] No findings", "[WARN] Stale", "[ERR] Broken", "> 1 more", "[HIGH]"}},
		{mode: output.Agent, want: []string{"Findings: 2", "OK: No findings", "WARN: Stale", "ERR: Broken", "> 1 more", "[HIGH]"}},
	}
	for _, tc := range cases {
		t.Run(tc.mode.String(), func(t *testing.T) {
			p := For(tc.mode)
			got := []string{
				p.Cards(Card{Label: "Findings", Value: "2"}),
				p.Success("No findings"),
				p.Warning("Stale"),
				p.Error("Broken"),
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

// TestForGivesPlainUnderAPlainMessagingMode keeps a rich page from mixing
// with the plain icons and border that dry/tui reads from the messaging
// mode.
func TestForGivesPlainUnderAPlainMessagingMode(t *testing.T) {
	prev := output.CurrentMode()
	t.Cleanup(func() { output.SetMode(prev) })
	output.SetMode(output.Plain)
	assert.Equal(t, output.Plain, For(output.Rich).Mode())
}
