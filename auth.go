package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/safedep/vet/internal/auth"
)

var (
	authInsightApiBaseUrl      string
	authControlPlaneApiBaseUrl string
	authTrialEmail             string
)

func newAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Configure and verify Insights API authentication",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("You must choose an appropriate command: configure, verify\n")
			os.Exit(1)
			return nil
		},
	}

	cmd.AddCommand(configureAuthCommand())
	cmd.AddCommand(verifyAuthCommand())
	cmd.AddCommand(trialsRegisterCommand())

	return cmd
}

func configureAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "configure",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Print("Enter API Key: ")
			key, err := term.ReadPassword(syscall.Stdin)
			if err != nil {
				panic(err)
			}

			err = auth.Configure(auth.Config{
				ApiUrl: authInsightApiBaseUrl,
				ApiKey: string(key),
			})

			if err != nil {
				panic(err)
			}

			os.Exit(1)
			return nil
		},
	}

	cmd.Flags().StringVarP(&authInsightApiBaseUrl, "api", "", auth.DefaultApiUrl(),
		"Base URL of Insights API")

	return cmd

}

func verifyAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "verify",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Printf("Verify auth command is currently work in progress\n")
			os.Exit(1)
			return nil
		},
	}

	return cmd
}

func trialsRegisterCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "trial",
		RunE: func(cmd *cobra.Command, args []string) error {
			client := auth.NewTrialRegistrationClient(auth.TrialConfig{
				Email:              authTrialEmail,
				ControlPlaneApiUrl: authControlPlaneApiBaseUrl,
			})

			res, err := client.Execute()
			if err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}

			fmt.Printf("Trial registration successful with Id:%s\n", res.Id)
			fmt.Printf("Check your email (%s) for API key and usage instructions\n", authTrialEmail)
			fmt.Printf("The trial API key will expire on %s\n", res.ExpiresAt.String())

			return nil
		},
	}

	cmd.Flags().StringVarP(&authTrialEmail, "email", "", "",
		"Email address to use for sending trial API key")
	cmd.Flags().StringVarP(&authControlPlaneApiBaseUrl, "control-plane", "",
		auth.DefaultControlPlaneApiUrl(), "Base URL of Control Plane API for registrations")

	return cmd
}
