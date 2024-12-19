package inspect

import (
	"github.com/spf13/cobra"
)

func NewPackageInspectCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Inspect an OSS package",
		Long: `Inspect an OSS package using deep inspection and analysis.
		This command will integrate with local and remote analysis services.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newPackageMalwareInspectCommand())
	return cmd
}
