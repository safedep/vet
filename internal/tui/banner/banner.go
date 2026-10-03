// Package banner prints the vet banner. It uses the banner of dry/tui, so
// vet looks like the other SafeDep tools.
package banner

import (
	"io"
	"strings"

	drybanner "github.com/safedep/dry/tui/banner"

	"github.com/safedep/vet/v2/internal/tui/output"
)

const art = "█░█ █▀▀ ▀█▀\n▀▄▀ ██▄ ░█░"

// Tagline is the line under the name.
const Tagline = "Supply chain security from SafeDep"

// Print writes the banner to stderr for a human. The plain mode, the agent
// mode and -q print nothing, so logs, CI output and agents stay clean.
func Print(version string) { PrintTo(output.Stderr(), version) }

// PrintTo writes the banner to w for a human.
func PrintTo(w io.Writer, version string) {
	if output.CurrentMode() != output.Rich || output.CurrentVerbosity() <= output.Silent {
		return
	}
	b := drybanner.Banner{Art: art, Name: "vet", Version: displayVersion(version), Tagline: Tagline}
	b.PrintTo(w)
	if _, err := io.WriteString(w, "\n"); err != nil {
		return
	}
}

// displayVersion drops the build metadata, as in +dirty, so that dry/tui
// shows a pseudo-version as dev (<commit>).
func displayVersion(v string) string {
	v, _, _ = strings.Cut(v, "+")
	return v
}
