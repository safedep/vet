package cloud

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/command"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/cloud"
)

var (
	keyName        string
	keyDescription string
	keyExpiresIn   int

	listKeysName           string
	listKeysIncludeExpired bool
	listKeysOnlyMine       bool
	listKeysPageSize       int
	listKeysPageToken      string

	deleteKeyId string
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
	cmd.AddCommand(newListKeyCommand())
	cmd.AddCommand(newDeleteKeyCommand())

	return cmd
}

func newDeleteKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete an API key",
		RunE:  command.RunCmd(executeDeleteKey),
	}

	cmd.Flags().StringVar(&deleteKeyId, "id", "", "ID of the API key to delete")
	_ = cmd.MarkFlagRequired("id")

	return cmd
}

func executeDeleteKey() error {
	client, err := auth.ControlPlaneClientConnection("vet-cloud-key-delete")
	if err != nil {
		return err
	}

	keyService, err := cloud.NewApiKeyService(client)
	if err != nil {
		return err
	}

	err = keyService.DeleteKey(deleteKeyId)
	if err != nil {
		return err
	}

	ui.PrintSuccess("API key deleted successfully.")
	return nil
}

func newListKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List API keys",
		RunE:  command.RunCmd(executeListKeys),
	}

	cmd.Flags().StringVar(&listKeysName, "name", "",
		"List keys with partial match on the name")
	cmd.Flags().BoolVar(&listKeysIncludeExpired, "include-expired", false,
		"Include expired keys in the list")
	cmd.Flags().BoolVar(&listKeysOnlyMine, "only-mine", false,
		"List only keys created by the current user")
	cmd.Flags().IntVar(&listKeysPageSize, "page-size", 0,
		"Number of keys to return per page (0 for server default)")
	cmd.Flags().StringVar(&listKeysPageToken, "page-token", "",
		"Page token for retrieving the next page of results")

	return cmd
}

func executeListKeys() error {
	client, err := auth.ControlPlaneClientConnection("vet-cloud-key-list")
	if err != nil {
		return err
	}

	keyService, err := cloud.NewApiKeyService(client)
	if err != nil {
		return err
	}

	keys, err := keyService.ListKeys(&cloud.ListApiKeyRequest{
		Name:           listKeysName,
		IncludeExpired: listKeysIncludeExpired,
		OnlyMine:       listKeysOnlyMine,
		PageSize:       uint32(listKeysPageSize),
		PageToken:      listKeysPageToken,
	})
	if err != nil {
		return err
	}

	if len(keys.Keys) == 0 {
		ui.PrintSuccess("No API keys found.")
		return nil
	}

	tbl := ui.NewTabler(ui.TablerConfig{})
	tbl.AddHeader("ID", "Name", "Expires At", "Description")

	for _, key := range keys.Keys {
		expiresAt := key.ExpiresAt.In(time.Local).Format(time.RFC822)
		tbl.AddRow(key.ID, key.Name, expiresAt, key.Desc)
	}

	if err := tbl.Finish(); err != nil {
		return err
	}

	if keys.NextPageToken != "" {
		ui.PrintMsg("\nNext page token: %s", keys.NextPageToken)
	}

	return nil
}

func newKeyCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Create a new API key",
		RunE:  command.RunCmd(executeCreateKey),
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
