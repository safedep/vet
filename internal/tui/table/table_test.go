package table

import (
	"strings"
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/safedep/dry/tui/output"
	"github.com/stretchr/testify/assert"
)

func TestFit(t *testing.T) {
	cases := []struct {
		name   string
		widths []int
		limit  int
		want   []int
	}{
		{name: "fits", widths: []int{5, 10}, limit: 80, want: []int{5, 10}},
		{name: "shrink widest", widths: []int{5, 40}, limit: 30, want: []int{5, 18}},
		{name: "shrink both", widths: []int{20, 20}, limit: 27, want: []int{10, 10}},
		{name: "stop at minimum", widths: []int{10, 10}, limit: 5, want: []int{minColumn, minColumn}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, fit(tc.widths, tc.limit))
		})
	}
}

func TestRenderTruncatesToWidth(t *testing.T) {
	output.SetMode(output.Plain)
	t.Cleanup(func() { output.SetMode(output.Rich) })

	long := "pkg:npm/" + strings.Repeat("very-long-package-name-", 5) + "@1.0.0"
	out := New().Headers("SEVERITY", "SUBJECT").Row("high", long).MaxWidth(50).Render()
	for _, line := range strings.Split(out, "\n") {
		assert.LessOrEqual(t, ansi.StringWidth(line), 50, line)
	}
	assert.Contains(t, out, "…")
	assert.Contains(t, out, "high")

	short := New().Headers("A").Row("b").MaxWidth(50).Render()
	assert.NotContains(t, short, "…")
}
