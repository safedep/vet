// Package output passes through dry/tui/output: the output mode, the
// verbosity, the terminal width and the stdout and stderr writers.
package output

import (
	"io"
	"os"

	"github.com/safedep/dry/tui/output"
	"golang.org/x/term"
)

// Mode is the messaging mode of stderr.
type Mode = output.Mode

const (
	Rich  = output.Rich
	Plain = output.Plain
	Agent = output.Agent
)

// Verbosity is the amount of stderr output.
type Verbosity = output.Verbosity

const (
	Silent  = output.Silent
	Normal  = output.Normal
	Verbose = output.Verbose
)

// SetMode sets the mode. --mode and SAFEDEP_OUTPUT use it.
func SetMode(m Mode) { output.SetMode(m) }

// CurrentMode returns the mode. It detects the mode on the first call.
func CurrentMode() Mode { return output.CurrentMode() }

// stdoutIsTerminal reports whether stdout is a terminal. Tests replace it.
var stdoutIsTerminal = func() bool { return term.IsTerminal(int(os.Stdout.Fd())) }

// DataMode is the mode of report data and printer data. It is the messaging
// mode, but plain in place of rich unless the data goes to stdout and stdout
// is a terminal. dry/tui detects the messaging mode from stderr, so a file,
// a pipe or a redirect of stdout would get rich text without this.
func DataMode(toStdout bool) Mode {
	m := CurrentMode()
	if m == Rich && (!toStdout || !stdoutIsTerminal()) {
		return Plain
	}
	return m
}

// SetVerbosity sets the verbosity.
func SetVerbosity(v Verbosity) { output.SetVerbosity(v) }

// CurrentVerbosity returns the verbosity.
func CurrentVerbosity() Verbosity { return output.CurrentVerbosity() }

// IsColorEnabled reports whether the output uses colour.
func IsColorEnabled() bool { return output.IsColorEnabled() }

// Width returns the terminal width, or a fallback when stdout is not a
// terminal.
func Width() int { return output.Width() }

// SetWidthOverride sets the width for tests. Zero removes the override.
func SetWidthOverride(n int) { output.SetWidthOverride(n) }

// Stdout returns the data writer.
func Stdout() io.Writer { return output.Stdout() }

// Stderr returns the message writer.
func Stderr() io.Writer { return output.Stderr() }

// SetWriters replaces the writers, for tests.
func SetWriters(stdout, stderr io.Writer) { output.SetWriters(stdout, stderr) }
