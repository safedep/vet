package endpoint

import "github.com/spf13/cobra"

// NewEndpointCommand returns the `vet endpoint` cobra subcommand tree.
// Today the only child is `scan`; future commands (e.g. `endpoint
// status`) attach here as the surface grows.
func NewEndpointCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "endpoint",
		Short: "Endpoint inventory and SafeDep Cloud sync",
		Long: `Operate on this endpoint's inventory: discover installed AI tools, MCP
servers, coding agents, and AI extensions. When SafeDep credentials are
configured the inventory is streamed to SafeDep Cloud so it appears in
the Endpoint Hub.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}
	cmd.AddCommand(newScanCommand())
	return cmd
}
