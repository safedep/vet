// Package version holds the "vet version" command.
package version

import (
	"runtime"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/tui/printer"
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

// New returns the "vet version" command.
func New(a *app.App) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show the version and the build of vet",
		Long: `Show the version of vet, the commit that it was built from, the Go version
and the platform. Use -o json to read the fields in a script.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			p, err := a.Printer()
			if err != nil {
				return err
			}
			i := Current()
			return p.Print(i, printer.Rows{
				Headers: []string{"VERSION", "COMMIT", "GO", "PLATFORM"},
				Rows:    [][]string{{i.Version, i.Commit, i.Go, i.Platform}},
			})
		},
	}
}
