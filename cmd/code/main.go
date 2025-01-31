package code

import (
	"os"

	"github.com/safedep/vet/internal/ui"
	"github.com/spf13/cobra"
)

var languageCodes []string

func NewCodeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "code",
		Short: "Analyze souce code",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	defaultAllLanguageCodes, err := getAllLanguageCodeStrings()
	failOnError("setup-default-languages", err)
	cmd.PersistentFlags().StringArrayVar(&languageCodes, "lang", defaultAllLanguageCodes, "Source code languages to analyze")

	cmd.AddCommand(newScanCommand())

	return cmd
}

func failOnError(stage string, err error) {
	if err != nil {
		ui.PrintError("%s failed due to error: %s", stage, err.Error())
		os.Exit(-1)
	}
}
