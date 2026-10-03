package checklist

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/tui/output"
)

func TestLines(t *testing.T) {
	t.Cleanup(func() {
		output.SetMode(output.Rich)
		output.SetWidthOverride(0)
	})
	items := []Item{
		{Status: Pass, Name: "vet.version", Text: "vet dev (8957dc6)"},
		{Status: Warn, Name: "install.path", Text: "vet is not on PATH", Fix: "Add the directory to PATH."},
		{Status: Fail, Name: "endpoint.malysis", Text: "malysis did not answer", Fix: "Check the network."},
		{Status: Pass, Name: "state.dir", Text: "ok", Fix: "never shown"},
	}
	cases := []struct {
		name string
		mode output.Mode
		want []string
	}{
		{name: "plain", mode: output.Plain, want: []string{
			"[OK]   vet.version       vet dev (8957dc6)",
			"[WARN] install.path      vet is not on PATH",
			"                         > Add the directory to PATH.",
			"[ERR]  endpoint.malysis  malysis did not answer",
			"                         > Check the network.",
			"[OK]   state.dir         ok",
		}},
		{name: "rich", mode: output.Rich, want: []string{
			"✓ vet.version       vet dev (8957dc6)",
			"⚠ install.path      vet is not on PATH",
			"                    › Add the directory to PATH.",
			"✗ endpoint.malysis  malysis did not answer",
			"                    › Check the network.",
			"✓ state.dir         ok",
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output.SetMode(tc.mode)
			got := Lines(items)
			for i := range got {
				got[i] = ansi.Strip(got[i])
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestLinesWrapsInRichMode(t *testing.T) {
	t.Cleanup(func() {
		output.SetMode(output.Rich)
		output.SetWidthOverride(0)
	})
	output.SetMode(output.Rich)
	output.SetWidthOverride(40)
	got := Lines([]Item{{Status: Pass, Name: "state.dir", Text: strings.Repeat("word ", 10)}})
	lines := strings.Split(ansi.Strip(strings.Join(got, "\n")), "\n")
	assert.Greater(t, len(lines), 1)
	for _, l := range lines {
		assert.LessOrEqual(t, ansi.StringWidth(l), 40, l)
		assert.True(t, strings.HasPrefix(l, "✓ state.dir  ") || strings.HasPrefix(l, "             "), l)
	}
}
