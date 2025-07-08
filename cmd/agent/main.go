package agent

import "github.com/spf13/cobra"

var (
	maxAgentSteps int

	// User wants the agent to answer a single question and not start the
	// interactive agent. Not all agents may support this.
	singlePrompt string
)

func NewAgentCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run an available AI agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.PersistentFlags().IntVar(&maxAgentSteps, "max-steps", 30, "The maximum number of steps for the agent executor")
	cmd.PersistentFlags().StringVarP(&singlePrompt, "prompt", "p", "", "A single prompt to run the agent with")

	cmd.AddCommand(newQueryAgentCommand())

	return cmd
}
