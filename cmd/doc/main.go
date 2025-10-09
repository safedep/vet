package doc

import (
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
)

func NewDocCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "doc",
		Short:  "Documentation generation internal utilities",
		Hidden: true, // Hide from vet public commands and docs itshelf, since its only build utility
	}

	cmd.AddCommand(newGenerateCommand())

	if err := doc.GenMarkdownTree(cmd, "./k9"); err != nil {
		panic(err)
	}

	return cmd
}
