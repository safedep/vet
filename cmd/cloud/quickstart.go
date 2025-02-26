package cloud

import (
	"fmt"
	"os"
	"time"

	controltowerv1pb "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/controltower/v1"
	controltowerv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/services/controltower/v1"
	"github.com/AlecAivazis/survey/v2"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/safedep/vet/internal/auth"
	"github.com/safedep/vet/internal/ui"
	"github.com/safedep/vet/pkg/cloud"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
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
	ui.PrintMsg("🚀 Starting SafeDep Cloud Quickstart...")
	ui.PrintMsg("👋 Hello! Let's get you onboarded..")

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

	ui.PrintMsg("✅ Your tenant is set to: %s", tenant.GetDomain())

	// Close the previous connection
	if err := conn.Close(); err != nil {
		ui.PrintError("❌ Oops! Something went wrong while closing cloud connection: %s", err.Error())
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

	ui.PrintMsg("✅ All done!")
	ui.PrintMsg("")
	ui.PrintMsg("🎉 You are all set! You can now start using SafeDep Cloud")

	// TODO: We need the ability to auto-detect the project name and version
	// and then use that to sync the results to SafeDep Cloud
	ui.PrintMsg("✨ Run `vet scan -D /path/to/code --report-sync to scan your code and sync the results to SafeDep Cloud")

	return nil
}

func quickStartSetupTenantFromAccess(userInfo *controltowerv1.GetUserInfoResponse) (*controltowerv1pb.Tenant, error) {
	if len(userInfo.GetAccess()) == 0 {
		ui.PrintError("❌ Oops! This is weird, you should have access to at least one tenant. Please contact support.")
		return nil, fmt.Errorf("no tenant access")
	}

	// If user has access to multiple tenants
	// Ask user about which tenant they want to use if they have more than one
	var tenant *controltowerv1pb.Tenant
	if len(userInfo.GetAccess()) > 1 {
		// Print all tenants with index
		var tenantOptions []string
		ui.PrintMsg("🔍 You have access to the following tenants:")
		for idx, tenant := range userInfo.GetAccess() {
			ui.PrintMsg("%s", fmt.Sprintf("  - [%d] %s", idx, tenant.GetTenant().GetDomain()))
			tenantOptions = append(tenantOptions, tenant.GetTenant().GetDomain())
		}

		// Ask user which tenant they want to use
		var tenantIndex int
		err := survey.AskOne(&survey.Select{
			Message: "🔍 Which tenant do you want to use?",
			Options: tenantOptions,
		}, &tenantIndex)
		if err != nil {
			ui.PrintError("❌ Oops! Something went wrong while asking which tenant to use: %s", err.Error())
			return nil, err
		}

		tenant = userInfo.GetAccess()[tenantIndex].GetTenant()
	} else {
		tenant = userInfo.GetAccess()[0].GetTenant()
	}

	if err := auth.PersistTenantDomain(tenant.GetDomain()); err != nil {
		ui.PrintError("❌ Oops! Something went wrong while persisting your tenant domain: %s", err.Error())
		return nil, err
	}

	return tenant, nil
}

func quickStartAuthentication() error {
	ui.PrintMsg("🔑 Start by creating an account or sign-in to your existing account")

	token, err := executeDeviceAuthFlow()
	if err != nil {
		ui.PrintError("❌ Oops! Something went wrong while authenticating you: %s", err.Error())
		ui.PrintMsg("ℹ️  If you are using email and password, ensure your email is verified.")
		return err
	}

	ui.PrintSuccess("✅ Successfully authenticated you!")

	ui.PrintMsg("🔑 Saving your cloud credentials in your local config...")
	if err := auth.PersistCloudTokens(token.Token, token.RefreshToken, ""); err != nil {
		ui.PrintError("❌ Oops! Something went wrong while saving your cloud credentials: %s", err.Error())
		return err
	}

	ui.PrintSuccess("✅ Successfully saved your cloud credentials!")

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
	ui.PrintMsg("🔍 Checking if you have an existing tenant...")

	userService, err := cloud.NewUserService(conn)
	if err != nil {
		ui.PrintError("❌ Oops! Something went wrong while creating user service: %s", err.Error())
		return nil, err
	}

	userInfo, err := userService.CurrentUserInfo()
	if err != nil {
		return quickStartCreateNewTenant(conn)
	}

	ui.PrintMsg("✅ You are already registered with SafeDep Cloud")
	return userInfo, nil
}

func quickStartCreateNewTenant(conn *grpc.ClientConn) (*controltowerv1.GetUserInfoResponse, error) {
	ui.PrintMsg("📝 Looks like you don't have an existing tenant. Let's create one for you...")

	userName, domain, err := quickStartGetTenantInputs()
	if err != nil {
		return nil, err
	}

	onboardingService, err := cloud.NewOnboardingService(conn)
	if err != nil {
		ui.PrintError("❌ Oops! Something went wrong while creating onboarding service: %s", err.Error())
		return nil, err
	}

	_, err = onboardingService.Register(&cloud.RegisterRequest{
		Name:      userName,
		Email:     registerEmail,
		OrgName:   "Quickstart Organization",
		OrgDomain: domain,
	})
	if err != nil {
		ui.PrintError("❌ Oops! Something went wrong while registering your tenant: %s", err.Error())
		return nil, err
	}

	ui.PrintSuccess("✅ Successfully created a new tenant!")
	ui.PrintMsg("🔑 Please wait while we get you onboarded...")

	userService, err := cloud.NewUserService(conn)
	if err != nil {
		ui.PrintError("❌ Oops! Something went wrong while creating user service: %s", err.Error())
		return nil, err
	}

	return userService.CurrentUserInfo()
}

func quickStartGetTenantInputs() (string, string, error) {
	var userName string
	err := survey.AskOne(&survey.Input{
		Message: "👤 What should we call you?",
		Default: "John Doe",
	}, &userName)
	if err != nil {
		ui.PrintError("❌ Oops! Something went wrong while asking for your name: %s", err.Error())
		return "", "", err
	}

	autoDomain := fmt.Sprintf("quickstart-%s", time.Now().Format("20060102150405"))
	var domain string
	err = survey.AskOne(&survey.Input{
		Message: "📝 We have automatically generated a domain for you. Here is your chance to update",
		Default: autoDomain,
	}, &domain)
	if err != nil {
		ui.PrintError("❌ Oops! Something went wrong while asking for your domain: %s", err.Error())
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
		Message: "🔑 Do you want to create a new API key for this tenant?",
		Default: true,
	}, &createAPIKey)
	if err != nil {
		ui.PrintError("❌ Oops! Something went wrong while asking if you want to create an API key: %s", err.Error())
		return err
	}

	if !createAPIKey {
		return nil
	}

	var showAPIKey bool
	err = survey.AskOne(&survey.Confirm{
		Message: "Would you like to see the API key in addition to configuring it?",
		Default: true,
	}, &showAPIKey)
	if err != nil {
		ui.PrintError("❌ Oops! Something went wrong while asking about showing the API key: %s", err.Error())
		return err
	}

	createApiKeyService, err := cloud.NewApiKeyService(conn)
	if err != nil {
		ui.PrintError("❌ Oops! Something went wrong while creating the API key service: %s", err.Error())
		return err
	}

	apiKey, err := createApiKeyService.CreateApiKey(&cloud.CreateApiKeyRequest{
		Name:         fmt.Sprintf("Quick Start API Key: %s", time.Now().Format("20060102150405")),
		Desc:         "This is a quick start API key created for you by vet",
		ExpiryInDays: 30,
	})
	if err != nil {
		ui.PrintError("❌ Oops! Something went wrong while creating the API key: %s", err.Error())
		return err
	}

	if err := auth.PersistApiKey(apiKey.Key, tenant.GetDomain()); err != nil {
		ui.PrintError("❌ Oops! Something went wrong while persisting the API key: %s", err.Error())
		return err
	}

	if showAPIKey {
		ui.PrintMsg("✅ Here is your API key: %s", text.BgGreen.Sprint(apiKey.Key))
		ui.PrintMsg("ℹ️ Your tenant domain is: %s", text.BgGreen.Sprint(tenant.GetDomain()))
		ui.PrintMsg("🔑 Please save this API key in a secure location, it will not be shown again.")
		ui.PrintMsg("🔒 Your key will expire on: %s", apiKey.ExpiresAt.Format(time.RFC3339))
	}

	return nil
}
