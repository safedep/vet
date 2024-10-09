package cloud

import (
	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/cloud"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/spf13/cobra"
)

func newWhoamiCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "whoami",
		Short: "Print information about the current user",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeWhoami()
			if err != nil {
				logger.Errorf("Failed to execute whoami: %v", err)
			}

			return nil
		},
	}

	return cmd
}

func executeWhoami() error {
	conn, err := auth.ControlPlaneClientConnection("vet-cloud-whoami")
	if err != nil {
		return err
	}

	userService, err := cloud.NewUserService(conn)
	if err != nil {
		return err
	}

	res, err := userService.CurrentUserInfo()
	if err != nil {
		return err
	}

	ui.PrintSuccess("Authenticated as: %s <%s>", res.GetUser().GetName(),
		res.GetUser().GetEmail())

	ui.PrintSuccess("Has access to the following tenants:")
	for _, access := range res.GetAccess() {
		ui.PrintSuccess("  - %s [%d]", access.GetTenant().GetDomain(),
			access.GetLevel())
	}

	return nil
}
