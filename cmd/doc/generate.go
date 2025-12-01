package doc

import (
	"fmt"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

var (
	// markdownOutDir is the output directory for markdown doc files
	markdownOutDir string

	// manOutDir is the output directory for troff (man markup) doc files
	manOutDir string
)

func newGenerateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate docs / manual artifacts",
		RunE: func(cmd *cobra.Command, args []string) error {
			// we specify the root (see, not parent) command since its the starting point for docs
			return runGenerateCommand(cmd.Root())
		},
	}

	cmd.PersistentFlags().StringVar(&markdownOutDir, "markdown", "", "The output directory for markdown doc files")
	cmd.PersistentFlags().StringVar(&manOutDir, "man", "", "The output directory for troff (man markup) doc files")

	cmd.PreRunE = func(cmd *cobra.Command, args []string) error {
		// At least one of the output directory is required
		if markdownOutDir == "" && manOutDir == "" {
			return errors.New("no output directory specified, at least one of the output directory is required")
		}

		return nil
	}

	return cmd
}

func runGenerateCommand(rootCmd *cobra.Command) error {
	// If markdown directory is specified
	if markdownOutDir != "" {
		// Create Markdown Manual
		if err := doc.GenMarkdownTree(rootCmd, markdownOutDir); err != nil {
			return errors.Wrap(err, "failed to generate markdown manual")
		}

		fmt.Println("Markdown manual doc created in: ", markdownOutDir)
	}

	// If troff (man markup) directory is specified
	if manOutDir != "" {
		// Create Troff (man markup) Manual
		manHeader := &doc.GenManHeader{
			Title:  "VET",
			Source: "SafeDep",
			Manual: "VET Manual",
		}

		if err := doc.GenManTree(rootCmd, manHeader, manOutDir); err != nil {
			return errors.Wrap(err, "failed to generate man (troff) manual")
		}

		fmt.Println("Troff (man markup) manual doc created in: ", manOutDir)
	}

	return nil
}
