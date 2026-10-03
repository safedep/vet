// Package logging sends the log lines of libraries to the vet output.
// Scalibr and the standard log package print each skipped or malformed
// file to stderr. A scan of a large project prints hundreds of these
// lines, so vet shows them only with -v.
package logging

import (
	stdlog "log"
	"strings"

	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/output"
)

// CaptureStandardLog sends the output of the standard log package to Emit.
func CaptureStandardLog() {
	stdlog.SetFlags(0)
	stdlog.SetPrefix("")
	stdlog.SetOutput(writer{})
}

// Emit prints a library log line on stderr with -v, and drops it with no -v.
func Emit(msg string) {
	msg = strings.TrimRight(msg, "\n")
	if msg == "" || output.CurrentVerbosity() != output.Verbose {
		return
	}
	tui.Faint("%s", msg)
}

type writer struct{}

func (writer) Write(p []byte) (int, error) {
	Emit(string(p))
	return len(p), nil
}
