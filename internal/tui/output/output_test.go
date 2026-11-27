package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDataModeIsRichOnlyOnATerminal keeps rich text out of a report file
// and out of a pipe when stderr is a terminal.
func TestDataModeIsRichOnlyOnATerminal(t *testing.T) {
	orig := stdoutIsTerminal
	t.Cleanup(func() { SetMode(Rich); stdoutIsTerminal = orig })
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
			stdoutIsTerminal = func() bool { return tc.terminal }
			assert.Equal(t, tc.want, DataMode(tc.toStdout))
		})
	}
}
