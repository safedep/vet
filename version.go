package main

import (
	"fmt"
	"os"
	runtimeDebug "runtime/debug"

	"github.com/spf13/cobra"
)

// When building with CI or Make, version is set using `ldflags`
var (
	version string
	commit  string
)

func init() {
	// Only use buildInfo if version wasn't set by ldflags, that is its being build by `go install`
	if version == "" {
		// Main.Version is based on the version control system tag or commit.
		// This useful when app is build with `go install`
		// See: https://antonz.org/go-1-24/#main-modules-version
		buildInfo, _ := runtimeDebug.ReadBuildInfo()
		version = buildInfo.Main.Version
	}
}

func newVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version and build information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(os.Stdout, "Version: %s\n", version)
			fmt.Fprintf(os.Stdout, "CommitSHA: %s\n", commit)

			return nil
		},
	}

	return cmd
}
