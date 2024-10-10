package cloud

import (
	"time"

	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/cloud"
	"github.com/safedep/vet/pkg/common/logger"
	"github.com/spf13/cobra"
)

var (
	keyName        string
	keyDescription string
	keyExpiresIn   int
)

func newKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "key",
		Short: "Manage API keys",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	cmd.AddCommand(newKeyCreateCommand())

	return cmd
}

func newKeyCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new API key",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeCreateKey()
			if err != nil {
				logger.Errorf("Failed to create API key: %v", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&keyName, "name", "", "Name of the API key")
	cmd.Flags().StringVar(&keyDescription, "description", "", "Description of the API key")
	cmd.Flags().IntVar(&keyExpiresIn, "expires-in", 30,
		"Number of days after which the API key will expire")

	_ = cmd.MarkFlagRequired("name")

	return cmd
}

func executeCreateKey() error {
	client, err := auth.ControlPlaneClientConnection("vet-cloud-key-create")
	if err != nil {
		return err
	}

	keyService, err := cloud.NewApiKeyService(client)
	if err != nil {
		return err
	}

	key, err := keyService.CreateApiKey(&cloud.CreateApiKeyRequest{
		Name:         keyName,
		Desc:         keyDescription,
		ExpiryInDays: keyExpiresIn,
	})

	if err != nil {
		return err
	}

	ui.PrintSuccess("API key created successfully.")
	ui.PrintSuccess("Key: %s", key.Key)
	ui.PrintSuccess("Expires at: %s", key.ExpiresAt.Format(time.RFC3339))

	return nil
}
