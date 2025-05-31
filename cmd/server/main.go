package server

import "github.com/spf13/cobra"

func NewServerCommand() *cobra.Command {
	cmd := cobra.Command{
		Use:   "server",
		Short: "Start available servers",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newMcpServerCommand())

	return &cmd
}
