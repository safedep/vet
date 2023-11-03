package main

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/exceptions"
	"github.com/spf13/cobra"
)

var (
	verbose              bool
	debug                bool
	noBanner             bool
	logFile              string
	globalExceptionsFile string
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
	cmd.PersistentFlags().BoolVarP(&noBanner, "no-banner", "", false, "Do not display the vet banner")
	cmd.PersistentFlags().StringVarP(&logFile, "log", "l", "", "Write command logs to file")
	cmd.PersistentFlags().StringVarP(&globalExceptionsFile, "exceptions", "e", "", "Load exceptions from file")

	cmd.AddCommand(newAuthCommand())
	cmd.AddCommand(newScanCommand())
	cmd.AddCommand(newQueryCommand())
	cmd.AddCommand(newVersionCommand())
	cmd.AddCommand(newConnectCommand())

	cobra.OnInitialize(func() {
		printBanner()
		loadExceptions()
		logger.SetLogLevel(verbose, debug)
	})

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadExceptions() {
	if globalExceptionsFile != "" {
		loader, err := exceptions.NewExceptionsFileLoader(globalExceptionsFile)
		if err != nil {
			logger.Fatalf("Exceptions loader: %v", err)
		}

		err = exceptions.Load(loader)
		if err != nil {
			logger.Fatalf("Exceptions loader: %v", err)
		}
	}
}

func printBanner() {
	if noBanner {
		return
	}

	bRet, err := strconv.ParseBool(os.Getenv("VET_DISABLE_BANNER"))
	if (err == nil) && (bRet) {
		return
	}

	ui.PrintBanner(banner)
}

// Redirect to file or discard log if empty
func redirectLogToFile(path string) {
	if !utils.IsEmptyString(path) {
		if path == "-" {
			logger.MigrateTo(os.Stdout)
		} else {
			logger.LogToFile(path)
		}
	} else {
		logger.MigrateTo(io.Discard)
	}
}

func failOnError(stage string, err error) {
	if err != nil {
		ui.PrintError("%s failed due to error: %s", stage, err.Error())
		os.Exit(-1)
	}
}
