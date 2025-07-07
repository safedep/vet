package agent

import "github.com/spf13/cobra"

var maxAgentSteps int

func NewAgentCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run an available AI agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.Flags().IntVar(&maxAgentSteps, "max-steps", 30, "The maximum number of steps for the agent executor")

	cmd.AddCommand(newQueryAgentCommand())

	return cmd
}
