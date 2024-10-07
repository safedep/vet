package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"

	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/common/logger"
)

var (
	authInsightApiBaseUrl      string
	authControlPlaneApiBaseUrl string
	authSyncApiBaseUrl         string
	authCommunity              bool
	authTenantDomain           string
)

func newAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Configure vet authentication",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("a valid sub-command is required")
		},
	}

	cmd.PersistentFlags().StringVarP(&authControlPlaneApiBaseUrl, "control-plane", "",
		auth.ControlTowerUrl(), "Base URL of Control Plane API")
	cmd.PersistentFlags().StringVarP(&authSyncApiBaseUrl, "sync", "", auth.SyncApiUrl(),
		"Base URL of Sync API")

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

			if !authCommunity {
				err = survey.AskOne(&survey.Password{
					Message: "Enter the API key",
				}, &key)
			} else {
				authInsightApiBaseUrl = auth.DefaultCommunityApiUrl()
			}

			if err != nil {
				logger.Fatalf("Failed to setup auth: %v", err)
			}

			if auth.TenantDomain() != "" && auth.TenantDomain() != authTenantDomain {
				ui.PrintWarning(fmt.Sprintf("Tenant domain mismatch. Existing: %s, New: %s, continue? ",
					auth.TenantDomain(), authTenantDomain))

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

			err = auth.Configure(auth.Config{
				ApiUrl:             authInsightApiBaseUrl,
				ApiKey:             string(key),
				ControlPlaneApiUrl: authControlPlaneApiBaseUrl,
				SyncApiUrl:         authSyncApiBaseUrl,
				Community:          authCommunity,
				TenantDomain:       authTenantDomain,
			})

			if err != nil {
				logger.Fatalf("Failed to configure auth: %v", err)
			}

			os.Exit(0)
			return nil
		},
	}

	cmd.Flags().StringVarP(&authTenantDomain, "tenant-domain", "", "",
		"Tenant domain for SafeDep Cloud")
	cmd.Flags().StringVarP(&authInsightApiBaseUrl, "api", "", auth.DefaultApiUrl(),
		"Base URL of Insights API")
	cmd.Flags().BoolVarP(&authCommunity, "community", "", false,
		"Use community API endpoint for Insights")

	_ = cmd.MarkFlagRequired("tenant-domain")

	return cmd
}

func verifyAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "verify",
		RunE: func(cmd *cobra.Command, args []string) error {
			if auth.CommunityMode() {
				ui.PrintSuccess("Running in Community Mode")
			}

			failOnError("auth/verify", auth.Verify(&auth.VerifyConfig{
				ControlPlaneApiUrl: authControlPlaneApiBaseUrl,
			}))

			ui.PrintSuccess("Authentication key is valid!")
			return nil
		},
	}

	return cmd
}
