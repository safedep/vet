package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var version string
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
