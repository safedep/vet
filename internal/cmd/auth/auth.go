// Package auth holds the "vet auth" commands. vet shares its credentials
// with pmg and the safedep cli through the dry/cloud keychain profiles.
package auth

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/credentials"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/printer"
	"github.com/safedep/vet/v2/internal/tui/prompt"
)

// New returns the "vet auth" command.
func New(a *app.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "auth",
		Short: "Sign in to SafeDep Cloud",
		Long: `vet works with no credentials, on the community endpoints. With an API key,
vet uses the API endpoints of your tenant. vet reads SAFEDEP_API_KEY and
SAFEDEP_TENANT_ID first, then the keychain profile of --profile, else
SAFEDEP_PROFILE, else "default". pmg and the safedep cli share the same
profiles.`,
	}
	c.AddCommand(newLogin(a), newStatus(a), newLogout(a))
	return c
}

// options returns the credential options of the run. The flag turns on the
// plaintext fallback for this command.
func options(a *app.App, fallback bool) (credentials.Options, error) {
	rt, err := a.Config(app.ConfigOptions{})
	if err != nil {
		return credentials.Options{}, err
	}
	c := rt.Config.Cloud
	return credentials.FromConfig(c.Profile, c.InsecureKeychainFallback || fallback, c.KeychainFile), nil
}

func newLogin(a *app.App) *cobra.Command {
	var tenant string
	var stdin, fallback bool
	c := &cobra.Command{
		Use:   "login",
		Short: "Save an API key in the keychain profile",
		Long: `Save a SafeDep API key and its tenant in the keychain profile. vet asks for
both, or reads the key from stdin with --api-key-stdin and the tenant from
--tenant, for a script. pmg and the safedep cli read the same profile.
On a machine with no OS keychain, --insecure-keychain-fallback stores the
credentials in a plaintext file, as the safedep cli does.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o, err := options(a, fallback)
			if err != nil {
				return err
			}
			key, err := apiKey(cmd.InOrStdin(), stdin)
			if err != nil {
				return err
			}
			if tenant == "" {
				if tenant, err = prompt.Prompt("Tenant domain (for example acme.safedep.io)"); err != nil {
					return askError(err, "the tenant", "Pass the tenant domain with --tenant")
				}
			}
			if strings.TrimSpace(key) == "" || strings.TrimSpace(tenant) == "" {
				return app.UsageError("an API key and a tenant are required", "Pass --api-key-stdin and --tenant.")
			}
			profile, err := credentials.Login(o, key, tenant)
			if err != nil {
				return err
			}
			tui.Success("Signed in to %s on profile %q. %s use this profile too.", strings.TrimSpace(tenant), profile, shared(profile))
			return nil
		},
	}
	f := c.Flags()
	f.StringVar(&tenant, "tenant", "", "Tenant domain, for example acme.safedep.io")
	f.BoolVar(&stdin, "api-key-stdin", false, "Read the API key from stdin")
	f.BoolVar(&fallback, "insecure-keychain-fallback", false, "Use a plaintext file when the machine has no OS keychain")
	return c
}

func apiKey(in io.Reader, stdin bool) (string, error) {
	if !stdin {
		key, err := prompt.Secret("API key")
		if err != nil {
			return "", askError(err, "the API key", "Pass --api-key-stdin and write the key to stdin.")
		}
		return key, nil
	}
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// askError turns a prompt that vet cannot show into a usage error that
// names what vet asks for and the flag that gives it.
func askError(err error, what, help string) error {
	if errors.Is(err, prompt.ErrAgentMode) || errors.Is(err, prompt.ErrNoTTY) {
		return app.UsageErrorCode(app.CodeNeedsConfirmation, fmt.Sprintf("vet cannot ask for %s in this mode", what), help)
	}
	return err
}

func newStatus(a *app.App) *cobra.Command {
	var fallback bool
	c := &cobra.Command{
		Use:   "status",
		Short: "Show the credentials that vet uses",
		Long: `Show the profile, the API key and its tenant, and the cloud access that
vet uses, with the source of each one. vet prints no secret: the table
shows the last 4 characters of the key, and -o json shows none.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			o, err := options(a, fallback)
			if err != nil {
				return err
			}
			st, err := credentials.StatusOf(o)
			if err != nil {
				return err
			}
			if st.Warning != "" {
				tui.Warning("%s", st.Warning)
			}
			p, err := a.Printer()
			if err != nil {
				return err
			}
			if err := p.Print(st, statusRows(st)); err != nil {
				return err
			}
			return tui.Hint("%s", statusHint(st))
		},
	}
	c.Flags().BoolVar(&fallback, "insecure-keychain-fallback", false, "Use a plaintext file when the machine has no OS keychain")
	return c
}

func statusRows(st *credentials.Status) printer.Rows {
	rows := printer.Rows{Headers: []string{"ITEM", "VALUE", "SOURCE"}}
	add := func(k, v, s string) { rows.Rows = append(rows.Rows, []string{k, v, s}) }
	add("Profile", st.Profile, st.ProfileSource)
	key, cloud := "none (community endpoints, rate limited)", "none"
	if st.APIKey != "" {
		key = "••••" + st.KeyHint
		if st.Tenant != "" {
			key += " (" + st.Tenant + ")"
		}
	}
	if st.Token != "" {
		cloud = st.Tenant
		if cloud == "" {
			cloud = "signed in"
		}
	}
	add("API key", key, st.APIKey)
	add("Cloud access", cloud, st.Token)
	return rows
}

// statusHint says how to save a key when there is none, and which tools
// read the same profile.
func statusHint(st *credentials.Status) string {
	shared := "The safedep CLI reads the same profile."
	if slices.Contains(st.SharedWith, "pmg") {
		shared = "pmg and the safedep CLI read the same profile."
	}
	if st.APIKey == "" {
		return "vet auth login saves an API key. " + shared
	}
	return shared
}

func newLogout(a *app.App) *cobra.Command {
	var fallback bool
	c := &cobra.Command{
		Use:   "logout",
		Short: "Delete the credentials of the keychain profile",
		Long: `Delete every credential of the keychain profile. pmg and the safedep cli
use the same profile, so they sign out too. The SAFEDEP_API_KEY and
SAFEDEP_TENANT_ID variables still apply.`,
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			o, err := options(a, fallback)
			if err != nil {
				return err
			}
			profile, err := credentials.Logout(o)
			if err != nil {
				return err
			}
			tui.Success("Signed out of profile %q. %s use this profile too.", profile, shared(profile))
			if _, ok := a.LookupEnv("SAFEDEP_API_KEY"); ok {
				tui.Warning("SAFEDEP_API_KEY is set, so vet still uses it.")
			}
			return nil
		},
	}
	c.Flags().BoolVar(&fallback, "insecure-keychain-fallback", false, "Use a plaintext file when the machine has no OS keychain")
	return c
}

func shared(profile string) string {
	if profile == "default" {
		return "pmg and the safedep cli"
	}
	return "The safedep cli can"
}
