// Package credentials resolves the SafeDep Cloud credentials of a run
// through dry/cloud, which pmg and the safedep cli share. vet works with no
// credentials: anonymous use is the default (decisions D11).
package credentials

import (
	"errors"
	"fmt"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/log"
	"github.com/safedep/dry/usefulerror"
)

// CodeIncomplete is the error code of a half credential. The command exits
// with code 2.
const CodeIncomplete = "credentials_incomplete"

// Result is the outcome of Resolve.
type Result struct {
	// Credentials is nil for an anonymous run.
	Credentials *cloud.Credentials
	// Profile is the keychain profile that vet read.
	Profile string
	// Warning explains why vet runs anonymously when a keychain failed.
	Warning string
}

// Anonymous reports whether the run has no credentials.
func (r *Result) Anonymous() bool { return r.Credentials == nil }

// Source names where the credentials came from: environment, keychain, or
// anonymous.
func (r *Result) Source() string {
	if r.Anonymous() {
		return "anonymous"
	}
	return r.Credentials.Source().String()
}

// TenantDomain returns the tenant of the credentials, or "".
func (r *Result) TenantDomain() string {
	if r.Anonymous() {
		return ""
	}
	d, err := r.Credentials.GetTenantDomain()
	if err != nil {
		return ""
	}
	return d
}

// Options are the inputs of Resolve.
type Options struct {
	// Profile is the --profile flag or the cloud.profile key. Empty means
	// SAFEDEP_PROFILE, then "default".
	Profile string
	// Resolver replaces the dry/cloud default resolver, for tests.
	Resolver cloud.CredentialResolver
	// KeychainOptions pass through to the dry/cloud resolver.
	KeychainOptions []cloud.KeychainOption
	// Fallback is cloud.insecure_keychain_fallback.
	Fallback bool
	// File is cloud.keychain_file.
	File string
}

// FromConfig returns the options of the cloud section of the config.
func FromConfig(profile string, fallback bool, file string) Options {
	return Options{Profile: profile, Fallback: fallback, File: file}
}

// keychainOptions returns the dry/cloud options of a profile.
func (o Options) keychainOptions(profile string) []cloud.KeychainOption {
	kopts := append([]cloud.KeychainOption{cloud.WithProfile(profile)}, o.KeychainOptions...)
	switch {
	case o.File != "":
		kopts = append(kopts, cloud.WithKeychainHandle(newFileKeychain(o.File)))
	case o.Fallback:
		kopts = append(kopts, cloud.WithInsecureFileFallback())
	}
	return kopts
}

// Resolve reads the API key credentials from the environment, then from the
// keychain profile. No credentials is not an error: the run is anonymous.
func Resolve(opts Options) (*Result, error) {
	profile := cloud.ResolveProfile(opts.Profile)
	res := &Result{Profile: profile}

	resolver := opts.Resolver
	if resolver == nil {
		r, err := cloud.NewDefaultCredentialResolver(cloud.CredentialTypeAPIKey, opts.keychainOptions(profile)...)
		if err != nil {
			return nil, fmt.Errorf("create credential resolver: %w", err)
		}
		defer func() {
			if cerr := r.Close(); cerr != nil {
				log.Warnf("close credential resolver: %v", cerr)
			}
		}()
		resolver = r
	}

	creds, err := resolver.Resolve()
	switch {
	case err == nil:
		res.Credentials = creds
		return res, nil
	case errors.Is(err, cloud.ErrIncompleteCredentials):
		return nil, usefulerror.NewUsefulError().
			WithCode(CodeIncomplete).
			WithHumanError(err.Error()).
			WithHelp("Set both SAFEDEP_API_KEY and SAFEDEP_TENANT_ID, or neither, or run vet auth login.").
			WithMsg(err.Error())
	case errors.Is(err, cloud.ErrMissingCredentials):
		return res, nil
	default:
		res.Warning = fmt.Sprintf("vet runs anonymously: %v", err)
		return res, nil
	}
}
