package cloud

import "github.com/spf13/cobra"

func NewCloudCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud",
		Short: "Manage and query cloud resources (control plane)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newCloudLoginCommand())
	cmd.AddCommand(newQueryCommand())
	cmd.AddCommand(newPingCommand())

	return cmd
}
