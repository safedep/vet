package cloud

import (
	"fmt"

	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/cloud"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/spf13/cobra"
)

var (
	registerEmail     string
	registerName      string
	registerOrgName   string
	registerOrgDomain string
)

func newRegisterCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "register",
		Short: "Register a new user and tenant",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := registerUserTenant()
			if err != nil {
				logger.Errorf("Failed to register user: %v", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&registerEmail, "email", "cloud@safedep.io", "Email of the user (not required for SafeDep cloud)")
	cmd.Flags().StringVar(&registerName, "name", "", "Name of the user")
	cmd.Flags().StringVar(&registerOrgName, "org-name", "", "Name of the organization")
	cmd.Flags().StringVar(&registerOrgDomain, "org-domain", "", "Domain of the organization")

	_ = cmd.MarkFlagRequired("name")
	_ = cmd.MarkFlagRequired("org-name")
	_ = cmd.MarkFlagRequired("org-domain")

	return cmd
}

func registerUserTenant() error {
	conn, err := auth.ControlPlaneClientConnection("vet-cloud-register")
	if err != nil {
		return err
	}

	onboardingService, err := cloud.NewOnboardingService(conn)
	if err != nil {
		return err
	}

	res, err := onboardingService.Register(&cloud.RegisterRequest{
		Name:      registerName,
		Email:     registerEmail,
		OrgName:   registerOrgName,
		OrgDomain: registerOrgDomain,
	})

	if err != nil {
		return err
	}

	ui.PrintSuccess("Registered user and tenant.")
	ui.PrintSuccess("Tenant domain: %s", res.TenantDomain)

	err = auth.PersistTenantDomain(res.TenantDomain)
	if err != nil {
		return fmt.Errorf("failed to persist tenant domain: %w", err)
	}

	return nil
}
