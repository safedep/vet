package cloud

import (
	"time"

	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/cloud"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/spf13/cobra"
)

func newPingCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ping",
		Short: "Ping the control plane to check authentication and connectivity",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := pingControlPlane()
			if err != nil {
				logger.Errorf("Failed to ping control plane: %v", err)
			}

			return nil
		},
	}

	return cmd
}

func pingControlPlane() error {
	conn, err := auth.ControlPlaneClientConnection("vet-cloud-ping")
	if err != nil {
		return err
	}

	pingService, err := cloud.NewPingService(conn)
	if err != nil {
		return err
	}

	pr, err := pingService.Ping()
	if err != nil {
		return err
	}

	ui.PrintSuccess("Ping successful. Started at %s, finished at %s",
		pr.StartedAt.Format(time.RFC3339), pr.FinishedAt.Format(time.RFC3339))
	return nil
}
