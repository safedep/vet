package main

import (
	"fmt"
	"os"
	runtimeDebug "runtime/debug"

	"github.com/spf13/cobra"
)

var version string
var commit string

func newVersionCommand() *cobra.Command {
	buildInfo, ok := runtimeDebug.ReadBuildInfo()

	if ok && version == "" {
		// Main.Version is based on the version control system tag or commit.
		// This useful when app is build with `go install`
		// See: https://antonz.org/go-1-24/#main-modules-version
		version = buildInfo.Main.Version
	}

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Show version and build information",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(os.Stdout, "Version: %s\n", version)
			fmt.Fprintf(os.Stdout, "CommitSHA: %s\n", commit)

			os.Exit(1)
			return nil
		},
	}

	return cmd
}
