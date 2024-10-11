package cloud

import (
	"context"
	"fmt"
	"net/http"

	"github.com/cli/oauth/device"
	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/spf13/cobra"
)

func newCloudLoginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login to SafeDep cloud for management tasks",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeDeviceAuthFlow()
			if err != nil {
				logger.Errorf("Failed to login to the SafeDep cloud: %v", err)
			}

			return nil
		},
	}

	return cmd
}

func executeDeviceAuthFlow() error {
	code, err := device.RequestCode(http.DefaultClient,
		auth.CloudIdentityServiceDeviceCodeUrl(),
		auth.CloudIdentityServiceClientId(),
		[]string{"offline_access", "openid", "profile", "email"},
		device.WithAudience(auth.CloudIdentityServiceAudience()))
	if err != nil {
		return fmt.Errorf("failed to request device code: %w", err)
	}

	ui.PrintSuccess("Please visit %s and enter the code %s to authenticate",
		code.VerificationURIComplete, code.UserCode)

	token, err := device.Wait(context.TODO(),
		http.DefaultClient, auth.CloudIdentityServiceTokenUrl(),
		device.WaitOptions{
			ClientID:   auth.CloudIdentityServiceClientId(),
			DeviceCode: code,
		})
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}

	return auth.PersistCloudTokens(token.Token,
		token.RefreshToken, tenantDomain)
}
