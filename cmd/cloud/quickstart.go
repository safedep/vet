package cloud

import (
	"fmt"
	"os"
	"time"

	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/AlecAivazis/survey/v2"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/cloud"
)

func newCloudQuickstartCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "quickstart",
		Short: "Quick onboarding to SafeDep Cloud and cli setup",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := executeCloudQuickstart()
			if err != nil {
				os.Exit(1)
			}

			return nil
		},
	}

	return cmd
}

// executeCloudQuickstart executes an opinionated quick start flow for the user
// with the goal of least friction on-boarding to SafeDep Cloud and configuring
// the cli with everything required to start using SafeDep Cloud services.
func executeCloudQuickstart() error {
	ui.PrintMsg("Starting SafeDep Cloud Quickstart")

	// This will execute cloud authentication flow and persist the cloud tokens
	// in the local config file.
	if err := quickStartAuthentication(); err != nil {
		return err
	}

	// Here we create a connection to the control plane with cloud token. This
	// connection may not be multi-tenant because user may not have any tenants
	// yet.
	conn, err := quickStartCreateConnection()
	if err != nil {
		return err
	}

	// Here we check if the user has any tenants. If not, we create a new one.
	userInfo, err := quickStartTenantSetup(conn)
	if err != nil {
		return err
	}

	// Here we get the tenant from the user info. The tenant domain is stored
	// in the local config file.
	tenant, err := quickStartSetupTenantFromAccess(userInfo)
	if err != nil {
		return err
	}

	ui.PrintMsg("Tenant set to: %s", tenant.GetDomain())

	// Close the previous connection
	if err := conn.Close(); err != nil {
		ui.PrintError("Failed to close cloud connection: %s", err.Error())
		return err
	}

	// Here we re-create the connection because we need a multi-tenant connection
	conn, err = quickStartCreateConnection()
	if err != nil {
		return err
	}

	if err := quickStartAPIKeyCreation(conn, tenant); err != nil {
		return err
	}

	ui.PrintSuccess("Setup complete. You can now start using SafeDep Cloud.")

	// TODO: We need the ability to auto-detect the project name and version
	// and then use that to sync the results to SafeDep Cloud
	ui.PrintMsg("Run `vet scan -D /path/to/code --report-sync` to scan your code and sync results to SafeDep Cloud")

	return nil
}

func quickStartSetupTenantFromAccess(userInfo *controltowerv1.GetUserInfoResponse) (*controltowerv1pb.Tenant, error) {
	if len(userInfo.GetAccess()) == 0 {
		ui.PrintError("No tenant access found. Please contact support.")
		return nil, fmt.Errorf("no tenant access")
	}

	// If user has access to multiple tenants
	// Ask user about which tenant they want to use if they have more than one
	var tenant *controltowerv1pb.Tenant
	if len(userInfo.GetAccess()) > 1 {
		// Print all tenants with index
		var tenantOptions []string
		ui.PrintMsg("You have access to the following tenants:")
		for idx, tenant := range userInfo.GetAccess() {
			ui.PrintMsg("%s", fmt.Sprintf("  - [%d] %s", idx, tenant.GetTenant().GetDomain()))
			tenantOptions = append(tenantOptions, tenant.GetTenant().GetDomain())
		}

		// Ask user which tenant they want to use
		var tenantIndex int
		err := survey.AskOne(&survey.Select{
			Message: "Which tenant do you want to use?",
			Options: tenantOptions,
		}, &tenantIndex)
		if err != nil {
			ui.PrintError("Failed to get tenant selection: %s", err.Error())
			return nil, err
		}

		tenant = userInfo.GetAccess()[tenantIndex].GetTenant()
	} else {
		tenant = userInfo.GetAccess()[0].GetTenant()
	}

	if err := auth.PersistTenantDomain(tenant.GetDomain()); err != nil {
		ui.PrintError("Failed to persist tenant domain: %s", err.Error())
		return nil, err
	}

	return tenant, nil
}

func quickStartAuthentication() error {
	ui.PrintMsg("Create an account or sign in to your existing account")

	token, err := executeDeviceAuthFlow()
	if err != nil {
		ui.PrintError("Authentication failed: %s", err.Error())
		ui.PrintMsg("If you are using email and password, ensure your email is verified.")
		return err
	}

	ui.PrintSuccess("Authenticated successfully.")

	ui.PrintMsg("Saving cloud credentials...")
	if err := auth.PersistCloudTokens(token.Token, token.RefreshToken, ""); err != nil {
		ui.PrintError("Failed to save cloud credentials: %s", err.Error())
		return err
	}

	ui.PrintSuccess("Cloud credentials saved.")

	return nil
}

func quickStartCreateConnection() (*grpc.ClientConn, error) {
	conn, err := auth.ControlPlaneClientConnection("vet-cloud-quickstart")
	if err != nil {
		ui.PrintError("❌ Oops! Something went wrong while creating cloud connection: %s", err.Error())
		return nil, err
	}

	return conn, nil
}

func quickStartTenantSetup(conn *grpc.ClientConn) (*controltowerv1.GetUserInfoResponse, error) {
	ui.PrintMsg("Checking for existing tenant...")

	userService, err := cloud.NewUserService(conn)
	if err != nil {
		ui.PrintError("Failed to create user service: %s", err.Error())
		return nil, err
	}

	userInfo, err := userService.CurrentUserInfo()
	if err != nil {
		return quickStartCreateNewTenant(conn)
	}

	ui.PrintMsg("Already registered with SafeDep Cloud.")
	return userInfo, nil
}

func quickStartCreateNewTenant(conn *grpc.ClientConn) (*controltowerv1.GetUserInfoResponse, error) {
	ui.PrintMsg("No existing tenant found. Creating a new one...")

	userName, domain, err := quickStartGetTenantInputs()
	if err != nil {
		return nil, err
	}

	onboardingService, err := cloud.NewOnboardingService(conn)
	if err != nil {
		ui.PrintError("Failed to create onboarding service: %s", err.Error())
		return nil, err
	}

	_, err = onboardingService.Register(&cloud.RegisterRequest{
		Name:      userName,
		Email:     registerEmail,
		OrgName:   "Quickstart Organization",
		OrgDomain: domain,
	})
	if err != nil {
		ui.PrintError("Failed to register tenant: %s", err.Error())
		return nil, err
	}

	ui.PrintSuccess("Tenant created successfully.")

	userService, err := cloud.NewUserService(conn)
	if err != nil {
		ui.PrintError("Failed to create user service: %s", err.Error())
		return nil, err
	}

	return userService.CurrentUserInfo()
}

func quickStartGetTenantInputs() (string, string, error) {
	var userName string
	err := survey.AskOne(&survey.Input{
		Message: "Your name:",
		Default: "John Doe",
	}, &userName)
	if err != nil {
		ui.PrintError("Failed to get name: %s", err.Error())
		return "", "", err
	}

	autoDomain := fmt.Sprintf("quickstart-%s", time.Now().Format("20060102150405"))
	var domain string
	err = survey.AskOne(&survey.Input{
		Message: "Tenant domain (auto-generated, can be changed):",
		Default: autoDomain,
	}, &domain)
	if err != nil {
		ui.PrintError("Failed to get domain: %s", err.Error())
		return "", "", err
	}

	if domain == "" {
		domain = autoDomain
	}

	return userName, domain, nil
}

func quickStartAPIKeyCreation(conn *grpc.ClientConn, tenant *controltowerv1pb.Tenant) error {
	var createAPIKey bool
	err := survey.AskOne(&survey.Confirm{
		Message: "Create a new API key for this tenant?",
		Default: true,
	}, &createAPIKey)
	if err != nil {
		ui.PrintError("Failed to get API key preference: %s", err.Error())
		return err
	}

	if !createAPIKey {
		return nil
	}

	var showAPIKey bool
	err = survey.AskOne(&survey.Confirm{
		Message: "Show the API key after creation?",
		Default: true,
	}, &showAPIKey)
	if err != nil {
		ui.PrintError("Failed to get show key preference: %s", err.Error())
		return err
	}

	createApiKeyService, err := cloud.NewApiKeyService(conn)
	if err != nil {
		ui.PrintError("Failed to create API key service: %s", err.Error())
		return err
	}

	apiKey, err := createApiKeyService.CreateApiKey(&cloud.CreateApiKeyRequest{
		Name:         fmt.Sprintf("Quick Start API Key: %s", time.Now().Format("20060102150405")),
		Desc:         "This is a quick start API key created for you by vet",
		ExpiryInDays: 30,
	})
	if err != nil {
		ui.PrintError("Failed to create API key: %s", err.Error())
		return err
	}

	if err := auth.PersistApiKey(apiKey.Key, tenant.GetDomain()); err != nil {
		ui.PrintError("Failed to persist API key: %s", err.Error())
		return err
	}

	if showAPIKey {
		ui.PrintMsg("API key: %s", text.BgGreen.Sprint(apiKey.Key))
		ui.PrintMsg("Expires: %s", apiKey.ExpiresAt.Format(time.RFC3339))
	}

	ui.PrintMsg("Tenant domain: %s", text.BgGreen.Sprint(tenant.GetDomain()))
	ui.PrintWarning("Save this API key in a secure location. It will not be shown again.")

	return nil
}
