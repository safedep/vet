package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	authInsightApiBaseUrl string
)

func newAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "auth",
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
			// Run auth.Configure()
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
