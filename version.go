package main

import (
	"fmt"
	"os"
	runtimeDebug "runtime/debug"

	"github.com/spf13/cobra"
)

// Main.Version is based on the version control system tag or commit.
// This useful when app is build with `go install`
// See: https://antonz.org/go-1-24/#main-modules-version
var buildInfo, _ = runtimeDebug.ReadBuildInfo()

// When building with CI or Make, version is set using `ldflags` but when building with `go install`
// it will be set on runtime using VCS TAG AND COMMITS
var version = buildInfo.Main.Version
var commit string

func newVersionCommand() *cobra.Command {
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
