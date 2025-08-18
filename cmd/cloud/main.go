package cloud

import (
	"fmt"

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
	cmd.AddCommand(newCloudQuickstartCommand())

	queryCmd := newQueryCommand()
	queryCmd.PreRunE = requireAccessTokenCheck

	pingCmd := newPingCommand()
	pingCmd.PreRunE = requireAccessTokenCheck

	whoamiCmd := newWhoamiCommand()
	whoamiCmd.PreRunE = requireAccessTokenCheck

	keyCmd := newKeyCommand()
	keyCmd.PreRunE = requireAccessTokenCheck

	cmd.AddCommand(queryCmd)
	cmd.AddCommand(pingCmd)
	cmd.AddCommand(whoamiCmd)
	cmd.AddCommand(keyCmd)

	cmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if tenantDomain != "" {
			auth.SetRuntimeCloudTenant(tenantDomain)
		}
	}

	return cmd
}

func requireAccessTokenCheck(cmd *cobra.Command, args []string) error {
	// Check if token was obtained/refreshed 5 mins ago
	// If > 5 mins, check the access token expiry
	// else return
	if auth.ShouldCheckAccessTokenExpiry() {
		// Check if access token is expired
		// If expired (ok), refresh the session
		if ok, err := auth.IsAccessTokenExpired(); err != nil {
			tenantDomainPlaceholder := auth.TenantDomain()
			if tenantDomainPlaceholder == "" {
				tenantDomainPlaceholder = "<your-tenant-domain>"
			}

			ui.PrintError("Automatic token refresh failed, please re-login using `vet cloud login --tenant %s`", tenantDomainPlaceholder)
			return fmt.Errorf("failed to check access token expiry: %w", err)
		} else if ok {
			ui.PrintMsg("Refreshing Access Token")
			return auth.RefreshCloudSession()
		}
	}
	return nil
}
