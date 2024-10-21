package cloud

import (
	"os"

	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/safedep/vet/internal/auth"
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

	tbl := table.NewWriter()
	tbl.SetOutputMirror(os.Stdout)

	tbl.AppendHeader(table.Row{"User", "Tenant", "Access Level"})
	tbl.AppendSeparator()

	for _, access := range res.GetAccess() {
		tbl.AppendRow(table.Row{res.GetUser().GetEmail(),
			access.GetTenant().GetDomain(), access.GetLevel()})
	}

	tbl.Render()
	return nil
}
