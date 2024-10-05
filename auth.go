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
	authInsightApiBaseUrl      string
	authControlPlaneApiBaseUrl string
	authCommunity              bool
)

func newAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "[Deprecated] Use cloud command",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("a valid sub-command is required")
		},
	}

	cmd.PersistentFlags().StringVarP(&authControlPlaneApiBaseUrl, "control-plane", "",
		auth.DefaultControlTowerUrl(), "Base URL of Control Plane API")

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

			err = auth.Configure(auth.Config{
				ApiUrl:             authInsightApiBaseUrl,
				ApiKey:             string(key),
				ControlPlaneApiUrl: authControlPlaneApiBaseUrl,
				Community:          authCommunity,
			})

			if err != nil {
				logger.Fatalf("Failed to configure auth: %v", err)
			}

			os.Exit(0)
			return nil
		},
	}

	cmd.Flags().StringVarP(&authInsightApiBaseUrl, "api", "", auth.DefaultApiUrl(),
		"Base URL of Insights API")
	cmd.Flags().BoolVarP(&authCommunity, "community", "", false,
		"Use community API endpoint for Insights")

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
