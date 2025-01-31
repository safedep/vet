package code

import (
	"github.com/safedep/vet/pkg/command"
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
	command.FailOnError("setup-default-languages", err)
	cmd.PersistentFlags().StringArrayVar(&languageCodes, "lang", defaultAllLanguageCodes, "Source code languages to analyze")

	cmd.AddCommand(newScanCommand())

	return cmd
}
