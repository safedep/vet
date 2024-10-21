package cloud

import (
	"fmt"

	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
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

	tbl := ui.NewTabler(ui.TablerConfig{})

	tbl.AddHeader("Email", "Tenant", "Access Level")
	for _, access := range res.GetAccess() {
		accessName := "UNSPECIFIED"
		if name, ok := controltowerv1.AccessLevel_name[int32(access.GetLevel())]; ok {
			accessName = name
		}

		tbl.AddRow(res.GetUser().GetEmail(),
			access.GetTenant().GetDomain(),
			fmt.Sprintf("%s (%d)", accessName, access.GetRole()))
	}

	return tbl.Finish()
}
