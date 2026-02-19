package ai

import "github.com/spf13/cobra"

func NewAICommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ai",
		Short: "AI tools usage discovery and analysis",
		Long: `Discover and audit AI tool usage across the local development environment.

AI coding agents, MCP servers, and extensions are often adopted by developers
without centralized visibility, creating Shadow AI. This command group helps
gain awareness of what AI tools are active, what permissions they hold, and
what external services they connect to.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newDiscoverCommand())
	return cmd
}
