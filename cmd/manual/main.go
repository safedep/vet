package manual

import (
	"fmt"

	"github.com/pkg/errors"

	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var (
	// mdManualOutDir is the output directory for markdown manual files
	mdManualOutDir string

	// manManualOutDir is the output directory for troff (man markup) manual files
	manManualOutDir string
)

func NewManualCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "manual",
		Short:  "Create docs / manual artifacts",
		Hidden: true, // Hide from vet core commands and docs itshelf, since its only build utility
		RunE: func(cmd *cobra.Command, args []string) error {
			// we specify the root (see, not parent) command since its the starting point for docs
			return createManualsCmd(cmd.Root())
		},
	}

	cmd.PersistentFlags().StringVar(&mdManualOutDir, "md-out", "", "The output directory for markdown manual files")
	cmd.PersistentFlags().StringVar(&manManualOutDir, "man-out", "", "The output directory for troff (man markup) manual files")

	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		if mdManualOutDir == "" && manManualOutDir == "" {
			return errors.New("no output directory specified")
		}

		return nil
	}

	return cmd
}

func createManualsCmd(rootCmd *cobra.Command) error {
	if mdManualOutDir != "" {
		// Create Markdown Manual
		if err := doc.GenMarkdownTree(rootCmd, mdManualOutDir); err != nil {
			return errors.Wrap(err, "failed to generate markdown manual")
		}

		fmt.Println("Markdown manual created in: ", mdManualOutDir)
	}

	if manManualOutDir != "" {
		// Create Troff (man markup) Manual
		manHeader := &doc.GenManHeader{
			Title:  "VET",
			Source: "SafeDep",
			Manual: "VET Manual",
		}

		if err := doc.GenManTree(rootCmd, manHeader, manManualOutDir); err != nil {
			return errors.Wrap(err, "failed to generate man (troff) manual")
		}

		fmt.Println("Troff (man markup) manual created in: ", manManualOutDir)
	}

	return nil
}
