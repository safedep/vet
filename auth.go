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
	authInsightApiBaseUrl string
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

	cmd.Flags().StringVarP(&authInsightApiBaseUrl, "api", "", "https://api.safedep.io/insights/v1",
		"Base URL of Insights API")

	return cmd

}

func verifyAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "verify",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Run auth.Verify()
			os.Exit(1)
			return nil
		},
	}

	return cmd
}
