package ai

import "github.com/spf13/cobra"

func NewAICommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai",
		Short: "AI tool discovery and analysis",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newDiscoverCommand())
	return cmd
}
