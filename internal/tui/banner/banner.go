// Package banner prints the vet banner. It uses the banner of dry/tui, so
// vet looks like the other SafeDep tools.
package banner

import (
	"io"
	"regexp"
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
	b := drybanner.Banner{Art: art, Name: "vet", Version: DisplayVersion(version), Tagline: Tagline}
	b.PrintTo(w)
	if _, err := io.WriteString(w, "\n"); err != nil {
		return
	}
}

// pseudoVersion matches a Go pseudo-version and captures its commit. It is
// the rule of dry/tui/banner, which does not export it.
var pseudoVersion = regexp.MustCompile(`^v\d+\.\d+\.\d+-\d{14}-([0-9a-f]{12})$`)

// DisplayVersion returns the version as the banner shows it. It drops the
// build metadata, as in +dirty, and shows a pseudo-version as
// dev (<commit>).
func DisplayVersion(v string) string {
	v, _, _ = strings.Cut(v, "+")
	if v == "" {
		return "dev"
	}
	if m := pseudoVersion.FindStringSubmatch(v); m != nil {
		return "dev (" + m[1][:7] + ")"
	}
	return v
}
