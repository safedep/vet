package cloud

import (
	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/ui"
	"github.com/spf13/cobra"
)

var (
	tenantDomain   string
	outputCSV      string
	outputMarkdown string
)

func NewCloudCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud",
		Short: "Manage and query cloud resources (control plane)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.PersistentFlags().StringVar(&tenantDomain, "tenant", "",
		"Tenant domain to use for the command")

	cmd.PersistentFlags().StringVar(&outputCSV, "csv", "",
		"Output table views to a CSV file")

	cmd.PersistentFlags().StringVar(&outputMarkdown, "markdown", "",
		"Output table views to a Markdown file")

	cmd.AddCommand(newCloudLoginCommand())
	cmd.AddCommand(newRegisterCommand())
	cmd.AddCommand(newQueryCommand())
	cmd.AddCommand(newPingCommand())
	cmd.AddCommand(newWhoamiCommand())
	cmd.AddCommand(newKeyCommand())
	cmd.AddCommand(newCloudQuickstartCommand())

	cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if tenantDomain != "" {
			auth.SetRuntimeCloudTenant(tenantDomain)
		}
		skipRefreshForCommands := map[string]bool{
			"login":      true,
			"quickstart": true,
		}
		if !skipRefreshForCommands[cmd.Name()] {
			err := auth.RefreshAccessToken()
			if err != nil {
				ui.PrintError("Failed to refresh access token. Please use 'vet cloud login' command to get new access and refresh token :%v", err.Error())
			}
		}
	}

	return cmd
}
