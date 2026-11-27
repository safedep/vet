package glyph

import (
	"testing"

	"github.com/safedep/dry/tui/output"
	"github.com/stretchr/testify/assert"
)

func TestFor(t *testing.T) {
	cases := []struct {
		mode output.Mode
		want Set
	}{
		{mode: output.Rich, want: Set{Sep: " · ", Ellipsis: "…", Step: "›"}},
		{mode: output.Plain, want: Set{Sep: ", ", Ellipsis: "...", Step: ">"}},
		{mode: output.Agent, want: Set{Sep: ", ", Ellipsis: "...", Step: ">"}},
	}
	for _, tc := range cases {
		t.Run(tc.mode.String(), func(t *testing.T) {
			assert.Equal(t, tc.want, For(tc.mode))
		})
	}
}
