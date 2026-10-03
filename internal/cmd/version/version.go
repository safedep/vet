// Package version holds the "vet version" command.
package version

import (
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/tui/banner"
	"github.com/safedep/vet/v2/internal/version"
)

// Info is the build information that "vet version" prints.
type Info struct {
	Version  string `json:"version"`
	Commit   string `json:"commit,omitempty"`
	Go       string `json:"go"`
	Platform string `json:"platform"`
}

// Current returns the build information of this binary.
func Current() Info {
	return Info{
		Version:  version.Version(),
		Commit:   version.Commit(),
		Go:       runtime.Version(),
		Platform: runtime.GOOS + "/" + runtime.GOARCH,
	}
}

// Line returns the build as one line, with the version as the banner
// shows it: vet <version> (<commit>) <go> <platform>.
func (i Info) Line() string {
	v := banner.DisplayVersion(i.Version)
	if c := i.Commit[:min(7, len(i.Commit))]; c != "" && !strings.Contains(v, c) {
		v += " (" + c + ")"
	}
	return "vet " + v + " " + i.Go + " " + i.Platform
}

// New returns the "vet version" command.
func New(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the version and the build of vet",
		Long: `Show the version of vet, the commit that it was built from, the Go version
and the platform on one line. Use -o json to read the fields in a script.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			p, err := a.Printer()
			if err != nil {
				return err
			}
			i := Current()
			return p.PrintText(i, i.Line())
		},
	}
}
