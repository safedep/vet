package main

import (
	"errors"
	"fmt"
	"os"

	"context"
	"net/http"

	"github.com/AlecAivazis/survey/v2"
	"github.com/cli/oauth/device"
	"github.com/safedep/vet/internal/connect"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/spf13/cobra"
)

func newConnectCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect with 3rd party apps",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("a valid sub-command is required")
		},
	}

	cmd.AddCommand(connectGithubCommand())

	return cmd
}

func connectGithubCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "github",
		RunE: func(cmd *cobra.Command, args []string) error {
			githubAccessToken, err := getAccessTokenFromUser()
			if err != nil {
				githubAccessToken, err = getAccessTokenViaDeviceFlow()
			}

			if err != nil {
				logger.Fatalf("Failed to connect with Github API: %s", err.Error())
			}

			err = connect.PersistGithubAccessToken(githubAccessToken)
			if err != nil {
				logger.Fatalf("Failed to persist Github connection token: %s", err.Error())
			}

			ui.PrintSuccess("Github Access Token configured and saved at '%s' for your convenience.", connect.GetConfigFileHint())
			ui.PrintSuccess("You can use vet to scan your github repositories")
			ui.PrintSuccess("Run the command to scan your github repository")
			ui.PrintSuccess("\tvet scan --github https://github.com/<Org|User>/<Repo>")

			os.Exit(1)
			return nil
		},
	}

	return cmd
}

func getAccessTokenFromUser() (string, error) {
	var by_github_acces_token string

	prompt := &survey.Select{
		Message: "Do you have access token ready?",
		Options: []string{"Y", "N"},
		Default: "Y",
	}

	err := survey.AskOne(prompt, &by_github_acces_token)
	if err != nil {
		return "", err
	}

	if by_github_acces_token != "Y" {
		return "", fmt.Errorf("user refused to provide access token")
	}

	password := &survey.Password{
		Message: "Provide your access token: ",
	}

	var accessToken string
	err = survey.AskOne(password, &accessToken)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func getAccessTokenViaDeviceFlow() (string, error) {
	var by_web_flow string
	prompt := &survey.Select{
		Message: "Do you want to connect with your Github account to continue?",
		Options: []string{"Y", "N"},
		Default: "Y",
	}

	err := survey.AskOne(prompt, &by_web_flow)
	if err != nil {
		return "", err
	}

	if by_web_flow != "Y" {
		return "", fmt.Errorf("user cancelled device flow")
	}

	ui.PrintMsg("Starting Github authentication using oauth2 device flow")

	token, err := connectGithubWithDeviceFlow()
	if err != nil {
		return "", err
	}

	return token, nil
}

func connectGithubWithDeviceFlow() (string, error) {
	clientID := connect.GetGithubOAuth2ClientId()
	scopes := []string{"repo", "read:org"}
	httpClient := http.DefaultClient

	logger.Debugf("Initiating Github device flow auth using clientId: %s", clientID)

	// TODO: We are coupling with Github cloud API here. Self-hosted Github enterprise won't work
	code, err := device.RequestCode(httpClient, "https://github.com/login/device/code", clientID, scopes)
	if err != nil {
		ui.PrintError("Error while requesting code from github: %s", err.Error())
		return "", err
	}

	ui.PrintMsg("Copy the code: %s", code.UserCode)
	ui.PrintMsg("Navigate to the URL and paste the code: %s", code.VerificationURI)

	// TODO: We are coupling with Github cloud API here. Self-hosted Github enterprise won't work
	accessToken, err := device.Wait(context.TODO(), httpClient,
		"https://github.com/login/oauth/access_token",
		device.WaitOptions{
			ClientID:   clientID,
			DeviceCode: code,
		})

	if err != nil {
		return "", err
	}

	logger.Debugf("Completed device flow with Github successfully")
	return accessToken.Token, nil
}
