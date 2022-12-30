package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var GITCOMMIT string
var VERSION string

func newVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "version",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Fprintf(os.Stdout, "Version: %s\n", VERSION)
			fmt.Fprintf(os.Stdout, "CommitSHA: %s\n", GITCOMMIT)

			os.Exit(1)
			return nil
		},
	}

	return cmd
}
