package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/spf13/cobra"
)

var (
	verbose bool
	debug   bool
)

var banner string = `
 .----------------.  .----------------.  .----------------.
| .--------------. || .--------------. || .--------------. |
| | ____   ____  | || |  _________   | || |  _________   | |
| ||_  _| |_  _| | || | |_   ___  |  | || | |  _   _  |  | |
| |  \ \   / /   | || |   | |_  \_|  | || | |_/ | | \_|  | |
| |   \ \ / /    | || |   |  _|  _   | || |     | |      | |
| |    \ ' /     | || |  _| |___/ |  | || |    _| |_     | |
| |     \_/      | || | |_________|  | || |   |_____|    | |
| |              | || |              | || |              | |
| '--------------' || '--------------' || '--------------' |
 '----------------'  '----------------'  '----------------'

`

func main() {
	cmd := &cobra.Command{
		Use:              "vet [OPTIONS] COMMAND [ARG...]",
		Short:            "[ Establish trust in open source software supply chain ]",
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
		printBanner()
		logger.SetLogLevel(verbose, debug)
	})

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func printBanner() {
	bRet, err := strconv.ParseBool(os.Getenv("VET_DISABLE_BANNER"))
	if (err != nil) || (!bRet) {
		fmt.Print(banner)
	}
}
