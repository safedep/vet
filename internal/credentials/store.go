package credentials

import (
	"errors"
	"fmt"
	"strings"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/log"
)

// Login saves an API key and its tenant in the keychain profile. pmg and
// the safedep cli read the same profile.
func Login(o Options, apiKey, tenant string) (string, error) {
	profile := cloud.ResolveProfile(o.Profile)
	st, err := cloud.NewKeychainCredentialStore(o.keychainOptions(profile)...)
	if err != nil {
		return profile, fmt.Errorf("open the keychain: %w", err)
	}
	defer closeStore(st)
	return profile, st.SaveAPIKeyCredential(strings.TrimSpace(apiKey), strings.TrimSpace(tenant))
}

// Logout deletes every field of the keychain profile.
func Logout(o Options) (string, error) {
	profile := cloud.ResolveProfile(o.Profile)
	st, err := cloud.NewKeychainCredentialStore(o.keychainOptions(profile)...)
	if err != nil {
		return profile, fmt.Errorf("open the keychain: %w", err)
	}
	defer closeStore(st)
	return profile, st.Clear()
}

func closeStore(st cloud.CredentialStore) {
	if err := st.Close(); err != nil {
		log.Warnf("close the keychain: %v", err)
	}
}

// Status describes the credentials of a profile with no secret value.
type Status struct {
	Profile       string `json:"profile"`
	ProfileSource string `json:"profile_source"`
	Tenant        string `json:"tenant,omitempty"`
	// APIKey is the data plane credential: its source, or "" when absent.
	APIKey string `json:"api_key_source,omitempty"`
	// KeyHint is the last 4 characters of the API key, for the table only.
	KeyHint string `json:"-"`
	// Token is the control plane credential: its source, or "".
	Token      string   `json:"token_source,omitempty"`
	SharedWith []string `json:"shared_with"`
	Warning    string   `json:"warning,omitempty"`
}

// StatusOf reads the credentials of the profile from the environment and
// the keychain. A half credential is the same error as in a scan.
func StatusOf(o Options) (*Status, error) {
	profile := cloud.ResolveProfile(o.Profile)
	st := &Status{Profile: profile, ProfileSource: profileSource(o.Profile), SharedWith: sharedWith(profile)}
	res, err := Resolve(o)
	if err != nil {
		return nil, err
	}
	st.Warning = res.Warning
	if !res.Anonymous() {
		st.APIKey, st.Tenant = res.Source(), res.TenantDomain()
		if key, err := res.Credentials.GetAPIKey(); err == nil && len(key) > 4 {
			st.KeyHint = key[len(key)-4:]
		}
	}
	r, err := cloud.NewKeychainCredentialResolver(cloud.CredentialTypeToken, o.keychainOptions(profile)...)
	if err != nil {
		return st, nil
	}
	defer func() {
		if err := r.Close(); err != nil {
			log.Warnf("close the keychain: %v", err)
		}
	}()
	tok, err := r.Resolve()
	switch {
	case err == nil:
		st.Token = tok.Source().String()
		if st.Tenant == "" {
			if d, err := tok.GetTenantDomain(); err == nil {
				st.Tenant = d
			}
		}
	case errors.Is(err, cloud.ErrMissingCredentials):
	default:
		log.Debugf("read the control plane token: %v", err)
	}
	return st, nil
}

func profileSource(explicit string) string {
	switch {
	case explicit != "":
		return "flag or config"
	case cloud.ResolveProfile("") != cloud.DefaultProfile:
		return "SAFEDEP_PROFILE"
	}
	return "default"
}

func sharedWith(profile string) []string {
	if profile == cloud.DefaultProfile {
		return []string{"safedep cli", "pmg"}
	}
	return []string{"safedep cli"}
}
