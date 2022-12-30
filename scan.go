package main

import (
	"os"

	"github.com/safedep/vet/pkg/common/logger"
	"github.com/spf13/cobra"
)

var (
	lockfiles     []string
	lockfileAs    string
	baseDirectory string
)

func newScanCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "scan",
		RunE: func(cmd *cobra.Command, args []string) error {
			startScan()
			return nil
		},
	}

	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	cmd.Flags().StringVarP(&baseDirectory, "directory", "D", wd,
		"The directory to scan for lockfiles")
	cmd.Flags().StringArrayVarP(&lockfiles, "lockfiles", "L", []string{},
		"List of lockfiles to scan")
	cmd.Flags().StringVarP(&baseDirectory, "lockfile-as", "", "",
		"Ecosystem to interpret the lockfile as")

	return cmd
}

func startScan() {
	logger.SetLogLevel(verbose, debug)
	logger.Infof("Starting vet scanner")
}
