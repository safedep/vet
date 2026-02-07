// Package agent provides a CLI for running agents.
package agent

import "github.com/spf13/cobra"

var (
	maxAgentSteps int

	// Use a fast model when available. Opinionated. Can be overridden by the
	// setting environment variables.
	fastMode bool

	// User wants the agent to answer a single question and not start the
	// interactive agent. Not all agents may support this.
	singlePrompt string

	// Enable context compaction to reduce LLM context window usage.
	compactContext bool
)

func NewAgentCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run an available AI agent",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.PersistentFlags().IntVar(&maxAgentSteps, "max-steps", 50, "The maximum number of steps for the agent executor")
	cmd.PersistentFlags().StringVarP(&singlePrompt, "prompt", "p", "", "A single prompt to run the agent with")
	cmd.PersistentFlags().BoolVar(&fastMode, "fast", false, "Prefer a fast model when available (compromises on advanced reasoning)")
	cmd.PersistentFlags().BoolVar(&compactContext, "compact", false, "Enable context compaction to reduce LLM context window usage")

	cmd.AddCommand(newQueryAgentCommand())
	cmd.AddCommand(newClawHubScannerCommand())

	return cmd
}
