package doc

import (
	"github.com/spf13/cobra"
)

func NewDocCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "doc",
		Short:  "Documentation generation internal utilities",
		Hidden: true, // Hide from vet public commands and docs itshelf, since its only build utility
	}

	cmd.AddCommand(newGenerateCommand())

	return cmd
}
