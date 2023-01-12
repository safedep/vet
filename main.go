package main

import (
	"fmt"
	"os"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	debug   bool
)

func main() {
	cmd := &cobra.Command{
		Use:              "vet [OPTIONS] COMMAND [ARG...]",
		Short:            "Vet your 3rd party dependencies for security risks",
		TraverseChildren: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}

			return fmt.Errorf("vet: %s is not a valid command", args[0])
		},
	}

	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Show verbose logs")
	cmd.PersistentFlags().BoolVarP(&debug, "debug", "d", false, "Show debug logs")

	cmd.AddCommand(newAuthCommand())
	cmd.AddCommand(newScanCommand())
	cmd.AddCommand(newVersionCommand())

	cobra.OnInitialize(func() {
		logger.SetLogLevel(verbose, debug)
	})

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
