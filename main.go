package main

import (
	"fmt"
	"io"
	"os"
	"strconv"

	"github.com/safedep/dry/utils"
	"github.com/safedep/vet/cmd/cloud"
	"github.com/safedep/vet/cmd/code"
	"github.com/safedep/vet/cmd/inspect"
	"github.com/safedep/vet/cmd/server"
	"github.com/safedep/vet/internal/analytics"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/safedep/vet/pkg/exceptions"
	"github.com/spf13/cobra"
)

var (
	verbose               bool
	debug                 bool
	noBanner              bool
	logFile               string
	globalExceptionsFile  string
	globalExceptionsExtra []string
)

const (
	vetName                 = "vet"
	vetInformationURI       = "https://github.com/safedep/vet"
	vetVendorName           = "SafeDep"
	vetVendorInformationURI = "https://safedep.io"
)

var vetPurl = "pkg:golang/safedep/vet@" + version

const banner string = `
Yb    dP 888888 888888
 Yb  dP  88__     88
  YbdP   88""     88
   YP    888888   88

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
	cmd.PersistentFlags().StringVarP(&logFile, "log", "l", "", "Write command logs to file, use - as for stdout")
	cmd.PersistentFlags().StringVarP(&globalExceptionsFile, "exceptions", "e", "", "Load exceptions from file")
	cmd.PersistentFlags().StringSliceVarP(&globalExceptionsExtra, "exceptions-extra", "", []string{}, "Load additional exceptions from file")

	cmd.AddCommand(newAuthCommand())
	cmd.AddCommand(newScanCommand())
	cmd.AddCommand(newQueryCommand())
	cmd.AddCommand(newVersionCommand())
	cmd.AddCommand(newConnectCommand())
	cmd.AddCommand(cloud.NewCloudCommand())
	cmd.AddCommand(code.NewCodeCommand())

	if checkIfPackageInspectCommandEnabled() {
		cmd.AddCommand(inspect.NewPackageInspectCommand())
	}

	if checkIfServerCommandEnabled() {
		cmd.AddCommand(server.NewServerCommand())
	}

	cobra.OnInitialize(func() {
		printBanner()
		loadExceptions()
		logger.SetLogLevel(verbose, debug)
	})

	defer analytics.Close()

	analytics.TrackCommandRun()
	analytics.TrackCI()

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func loadExceptions() {
	loadExceptionsFromFile(globalExceptionsFile)

	for _, extra := range globalExceptionsExtra {
		loadExceptionsFromFile(extra)
	}
}

func loadExceptionsFromFile(file string) {
	if file == "" {
		return
	}

	loader, err := exceptions.NewExceptionsFileLoader(file)
	if err != nil {
		logger.Fatalf("Failed to create Exceptions loader: %v", err)
	}

	err = exceptions.Load(loader)
	if err != nil {
		logger.Fatalf("Failed to load exceptions: %v", err)
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

func checkIfPackageInspectCommandEnabled() bool {
	// Enabled by default now that we have tested this for a while
	return true
}

func checkIfServerCommandEnabled() bool {
	// Enabled by default but keep option open for disabling
	// based on remote config or user preference
	return true
}

// Redirect to file or discard log if empty
func redirectLogToFile(path string) {
	logger.Debugf("Redirecting logger output to: %s", path)

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
