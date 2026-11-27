package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDataModeIsRichOnlyOnATerminal keeps rich text out of a report file
// and out of a pipe when stderr is a terminal.
func TestDataModeIsRichOnlyOnATerminal(t *testing.T) {
	prev := CurrentMode()
	t.Cleanup(func() { SetMode(prev); SetStdoutTerminal(nil) })
	cases := []struct {
		name     string
		mode     Mode
		toStdout bool
		terminal bool
		want     Mode
	}{
		{name: "stdout on a terminal", mode: Rich, toStdout: true, terminal: true, want: Rich},
		{name: "stdout to a pipe", mode: Rich, toStdout: true, want: Plain},
		{name: "file", mode: Rich, terminal: true, want: Plain},
		{name: "plain", mode: Plain, toStdout: true, terminal: true, want: Plain},
		{name: "agent", mode: Agent, toStdout: true, terminal: true, want: Agent},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			SetMode(tc.mode)
			SetStdoutTerminal(func() bool { return tc.terminal })
			assert.Equal(t, tc.want, DataMode(tc.toStdout))
		})
	}
}

// TestDrawableNeverMixesModes keeps a rich drawing to a rich messaging mode.
// dry/tui reads the messaging mode for its icons and its border.
func TestDrawableNeverMixesModes(t *testing.T) {
	prev := CurrentMode()
	t.Cleanup(func() { SetMode(prev) })
	cases := []struct{ messaging, asked, want Mode }{
		{messaging: Rich, asked: Rich, want: Rich},
		{messaging: Plain, asked: Rich, want: Plain},
		{messaging: Agent, asked: Rich, want: Plain},
		{messaging: Rich, asked: Agent, want: Agent},
	}
	for _, tc := range cases {
		SetMode(tc.messaging)
		assert.Equal(t, tc.want, Drawable(tc.asked), "%s under %s", tc.asked, tc.messaging)
	}
}
