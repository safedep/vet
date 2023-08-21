package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"context"
	"net/http"

	"github.com/AlecAivazis/survey/v2"
	"github.com/cli/oauth/device"
	"github.com/safedep/vet/internal/connect"
	"github.com/spf13/cobra"
)

var (
	githubAccessToken string
)

func newConnectCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connect",
		Short: "Connect Vet with 3rd Party Apps",
		RunE: func(cmd *cobra.Command, args []string) error {
			return errors.New("a valid sub-command is required")
		},
	}

	cmd.AddCommand(connectGithubCommand())
	cmd.AddCommand()

	return cmd
}

func connectGithubCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use: "github",
		RunE: func(cmd *cobra.Command, args []string) error {
			var ok bool
			var err error

			githubAccessToken, ok = getAccessTokenFromUser()
			if !ok {
				githubAccessToken, ok = getAccessTokenViaDeviceFlow()
			}

			if ok {
				// Persist the token for future reference
				err = connect.Configure(connect.Config{
					GithubAccessToken: githubAccessToken,
				})

				if err != nil {
					panic(err)
				}

				fmt.Printf(`Github Access Token Configured and Saved at %s for your convenience 
					You cna use vet to scan your github repos.`, connect.GetConfigFile())

				fmt.Printf(`Run the command to scan your github repos:
					vet scan ...`)
			}

			os.Exit(1)
			return nil
		},
	}

	return cmd
}

func getAccessTokenFromUser() (string, bool) {
	var by_github_acces_token string

	prompt := &survey.Select{
		Message: "Do you have Access Token Ready?",
		Options: []string{"Y", "N"},
		Default: "Y",
	}
	_ = survey.AskOne(prompt, &by_github_acces_token)

	if by_github_acces_token == "Y" { // Github access token flow
		prompt := &survey.Password{
			Message: "Paste Your Access Token: ",
		}
		_ = survey.AskOne(prompt, &githubAccessToken)

		return githubAccessToken, true
	}

	// Return user opted not to provide github access toke
	return "", false
}

func getAccessTokenViaDeviceFlow() (string, bool) {
	var by_web_flow string
	prompt := &survey.Select{
		Message: "You must Connect with your Github Account to continue?",
		Options: []string{"Y", "N"},
		Default: "Y",
	}
	_ = survey.AskOne(prompt, &by_web_flow)
	if by_web_flow == "Y" {
		fmt.Println("Starting Github Authenitcation via Device Flow...")
		providedToken, err := connectGithubWithDeviceFlow()
		if err != nil {
			fmt.Printf("Error while initiating Device Flow Authentication: \n\t %s", err.Error())
			return "", false
		}
		return providedToken, true
	}

	fmt.Println("Can not proceed. Need Github Access. Run the connect again.")
	return "", false
}

// Initiate Device Authentication
func connectGithubWithDeviceFlow() (string, error) {
	clientID := strings.ToLower(os.Getenv("VET_GITHUB_CLIENT_ID"))
	if clientID == "" {
		clientID = "163517854a5c067ce32f" // Sample clientId
	}
	if clientID == "" {
		return "", fmt.Errorf("missing Client ID. Set Env Variable %s to provide it", "VET_GITHUB_CLIENT_ID")
	}
	scopes := []string{"repo", "read:org"}
	httpClient := http.DefaultClient

	code, err := device.RequestCode(httpClient, "https://github.com/login/device/code", clientID, scopes)
	if err != nil {
		fmt.Printf("Error while requesting code from github %v", err)
		return "", err
	}

	fmt.Printf("Copy the code: %s\n", code.UserCode)
	fmt.Printf("then open the link: %s\n", code.VerificationURI)

	accessToken, err := device.Wait(context.TODO(), httpClient, "https://github.com/login/oauth/access_token", device.WaitOptions{
		ClientID:   clientID,
		DeviceCode: code,
	})
	if err != nil {
		return "", err
	}

	return accessToken.Token, nil
}
