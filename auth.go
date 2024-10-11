package main

import (
	"errors"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"

	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/common/logger"
)

var (
	authTenantDomain string
)

func newAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Configure vet authentication",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("a valid sub-command is required")
		},
	}

	cmd.AddCommand(configureAuthCommand())
	cmd.AddCommand(verifyAuthCommand())

	return cmd
}

func configureAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "configure",
		RunE: func(cmd *cobra.Command, args []string) error {
			var key string
			var err error

			err = survey.AskOne(&survey.Password{
				Message: "Enter the API key",
			}, &key)
			if err != nil {
				logger.Fatalf("Failed to setup auth: %v", err)
			}

			if auth.TenantDomain() != "" && auth.TenantDomain() != authTenantDomain {
				ui.PrintWarning("Tenant domain mismatch. Existing: %s, New: %s, continue? ",
					auth.TenantDomain(), authTenantDomain)

				var confirm bool
				err = survey.AskOne(&survey.Confirm{
					Message: "Do you want to continue?",
				}, &confirm)

				if err != nil {
					logger.Fatalf("Failed to setup auth: %v", err)
				}

				if !confirm {
					return nil
				}
			}

			auth.SetRuntimeCloudTenant(authTenantDomain)
			auth.SetRuntimeApiKey(key)

			err = auth.Verify()
			if err != nil {
				logger.Fatalf("Failed to verify auth: %v", err)
			}

			err = auth.PersistApiKey(key, authTenantDomain)
			if err != nil {
				logger.Fatalf("Failed to configure auth: %v", err)
			}

			os.Exit(0)
			return nil
		},
	}

	cmd.Flags().StringVarP(&authTenantDomain, "tenant", "", "",
		"Tenant domain for SafeDep Cloud")

	_ = cmd.MarkFlagRequired("tenant")

	return cmd
}

func verifyAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "verify",
		RunE: func(cmd *cobra.Command, args []string) error {
			if auth.CommunityMode() {
				ui.PrintSuccess("Running in Community Mode")
			}

			failOnError("auth/verify", auth.Verify())

			ui.PrintSuccess("Authentication key is valid!")
			return nil
		},
	}

	return cmd
}
