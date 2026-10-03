// Package output passes through dry/tui/output: the output mode, the
// verbosity, the terminal width and the stdout and stderr writers.
package output

import (
	"io"

	"github.com/safedep/dry/tui/output"
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
