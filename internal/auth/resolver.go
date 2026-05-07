package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/safedep/dry/cloud"
)

// ErrNoCredentials is returned when no source in the resolution chain has
// both an API key and a tenant identifier configured. Sources that hold no
// credentials report this sentinel so the layered resolver can fall through
// to the next source. Real backend failures (a keychain that errored out,
// a corrupt config file) propagate verbatim and stop the chain — they are
// not "no credentials", they are a broken source.
var ErrNoCredentials = errors.New("auth: no credentials configured")

// Credentials carries the data-plane API key plus the tenant identifier the
// resolver chain produces. Field names mirror the existing helpers in
// auth.go so downstream code can adopt the resolver without adapter glue.
type Credentials struct {
	APIKey   string
	TenantID string
}

// Resolver discovers credentials at request time. Implementations must be
// safe to call concurrently when the underlying sources are.
type Resolver interface {
	Resolve(ctx context.Context) (Credentials, error)
}

// source is the narrow contract every layer in the chain implements. It is
// unexported on purpose: external packages add layers via Option, not by
// implementing the interface directly.
type source interface {
	resolve(ctx context.Context) (Credentials, error)
}

// Option configures NewLayeredResolver. The only documented option today is
// WithSource which appends an extra layer; we keep Option as a functional
// option so future extensions slot in without changing the constructor's
// signature.
type Option func(*layeredResolver)

// WithSource appends a custom source to the layered resolver. The source is
// consulted after the documented defaults in the order it was passed. Tests
// use this to inject deterministic stubs without reaching into package
// internals.
func WithSource(s source) Option {
	return func(r *layeredResolver) {
		r.sources = append(r.sources, s)
	}
}

// NewLayeredResolver returns a Resolver that walks credential sources in
// order:
//
//  1. vet env vars + vet-auth.yml (via auth.ApiKey / auth.TenantDomain;
//     covers SAFEDEP_API_KEY / SAFEDEP_TENANT_ID and their VET_ aliases).
//  2. DRY keychain provider, constructed without an insecure file fallback.
//
// A source that reports ErrNoCredentials triggers a fall-through; any other
// error stops the chain immediately. When every source is empty the resolver
// returns ErrNoCredentials so callers can branch on the sentinel.
func NewLayeredResolver(opts ...Option) Resolver {
	return newLayeredResolver([]source{
		&vetEnvFileSource{
			apiKey:       ApiKey,
			tenantDomain: TenantDomain,
		},
		&dryKeychainSource{
			newResolver: defaultDryKeychainResolver,
		},
	}, opts...)
}

func newLayeredResolver(sources []source, opts ...Option) *layeredResolver {
	r := &layeredResolver{sources: sources}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

type layeredResolver struct {
	sources []source
}

// Resolve walks the source chain. The first source that reports a credential
// wins; ErrNoCredentials fall through; anything else aborts the walk.
func (r *layeredResolver) Resolve(ctx context.Context) (Credentials, error) {
	for _, s := range r.sources {
		creds, err := s.resolve(ctx)
		if err == nil {
			return creds, nil
		}
		if errors.Is(err, ErrNoCredentials) {
			continue
		}
		return Credentials{}, err
	}
	return Credentials{}, ErrNoCredentials
}

// vetEnvFileSource consults vet's existing env-var + vet-auth.yml resolution
// chain. The hooks are function values so tests can substitute deterministic
// readers without touching globals.
type vetEnvFileSource struct {
	apiKey       func() string
	tenantDomain func() string
}

func (s *vetEnvFileSource) resolve(_ context.Context) (Credentials, error) {
	apiKey := s.apiKey()
	tenant := s.tenantDomain()
	if apiKey == "" || tenant == "" {
		return Credentials{}, ErrNoCredentials
	}
	return Credentials{APIKey: apiKey, TenantID: tenant}, nil
}

// dryKeychainSource consults the DRY keychain via cloud.NewKeychainCredentialResolver
// for an API-key credential. The keychain is constructed without the
// insecure file fallback; headless and WSL environments are served by
// the vet env layer (1).
//
// Construction is lazy so a missing keychain backend (e.g. headless
// Linux without DBus) only surfaces when this layer is reached.
// ErrMissingCredentials translates to ErrNoCredentials; everything else
// propagates verbatim.
type dryKeychainSource struct {
	// newResolver constructs the underlying DRY resolver. Tests substitute
	// a stub; production wires defaultDryKeychainResolver.
	newResolver func() (cloud.CloseableCredentialResolver, error)
}

func defaultDryKeychainResolver() (cloud.CloseableCredentialResolver, error) {
	// No KeychainOption is passed: insecure file fallback stays disabled,
	// and the default profile is used. Headless and WSL environments are
	// served by the env-var path at layer 1, not by a plaintext file.
	return cloud.NewKeychainCredentialResolver(cloud.CredentialTypeAPIKey)
}

func (s *dryKeychainSource) resolve(_ context.Context) (Credentials, error) {
	resolver, err := s.newResolver()
	if err != nil {
		return Credentials{}, fmt.Errorf("auth: keychain unavailable: %w", err)
	}
	defer func() { _ = resolver.Close() }()

	creds, err := resolver.Resolve()
	if err != nil {
		if errors.Is(err, cloud.ErrMissingCredentials) {
			return Credentials{}, ErrNoCredentials
		}
		return Credentials{}, fmt.Errorf("auth: keychain resolve: %w", err)
	}

	apiKey, err := creds.GetAPIKey()
	if err != nil {
		return Credentials{}, fmt.Errorf("auth: keychain credentials: %w", err)
	}
	tenant, err := creds.GetTenantDomain()
	if err != nil {
		if errors.Is(err, cloud.ErrMissingCredentials) {
			return Credentials{}, ErrNoCredentials
		}
		return Credentials{}, fmt.Errorf("auth: keychain credentials: %w", err)
	}
	return Credentials{APIKey: apiKey, TenantID: tenant}, nil
}
