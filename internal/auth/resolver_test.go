package auth

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/safedep/dry/cloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubSource implements the unexported source interface for tests.
type stubSource struct {
	creds Credentials
	err   error
	calls int
}

func (s *stubSource) resolve(_ context.Context) (Credentials, error) {
	s.calls++
	return s.creds, s.err
}

func TestLayeredResolver_FirstSourceReturnsCredentials(t *testing.T) {
	first := &stubSource{creds: Credentials{APIKey: "k1", TenantID: "t1"}}
	second := &stubSource{err: ErrNoCredentials}

	r := newLayeredResolver([]source{first, second})

	got, err := r.Resolve(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "k1", got.APIKey)
	assert.Equal(t, "t1", got.TenantID)
	assert.Equal(t, 1, first.calls)
	assert.Equal(t, 0, second.calls, "second source must not be consulted once first succeeds")
}

func TestLayeredResolver_FallsThroughOnErrNoCredentials(t *testing.T) {
	first := &stubSource{err: ErrNoCredentials}
	second := &stubSource{creds: Credentials{APIKey: "k2", TenantID: "t2"}}

	r := newLayeredResolver([]source{first, second})

	got, err := r.Resolve(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "k2", got.APIKey)
	assert.Equal(t, "t2", got.TenantID)
	assert.Equal(t, 1, first.calls)
	assert.Equal(t, 1, second.calls)
}

func TestLayeredResolver_AllSourcesEmptyReturnsErrNoCredentials(t *testing.T) {
	first := &stubSource{err: ErrNoCredentials}
	second := &stubSource{err: ErrNoCredentials}

	r := newLayeredResolver([]source{first, second})

	_, err := r.Resolve(context.Background())

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCredentials)
}

func TestLayeredResolver_NonSentinelErrorPropagatesImmediately(t *testing.T) {
	boom := errors.New("keychain backend exploded")
	first := &stubSource{err: boom}
	second := &stubSource{creds: Credentials{APIKey: "k2", TenantID: "t2"}}

	r := newLayeredResolver([]source{first, second})

	_, err := r.Resolve(context.Background())

	require.Error(t, err)
	assert.ErrorIs(t, err, boom)
	assert.Equal(t, 1, first.calls)
	assert.Equal(t, 0, second.calls, "later sources must not be consulted after a real error")
}

func TestLayeredResolver_WrappedErrNoCredentialsFallsThrough(t *testing.T) {
	// A source can wrap ErrNoCredentials with context. Fall-through must
	// still kick in via errors.Is, not equality.
	wrapped := &stubSource{err: errNoCredentialsf("wrapped: %w", ErrNoCredentials)}
	good := &stubSource{creds: Credentials{APIKey: "k", TenantID: "t"}}

	r := newLayeredResolver([]source{wrapped, good})

	got, err := r.Resolve(context.Background())

	require.NoError(t, err)
	assert.Equal(t, "k", got.APIKey)
	assert.Equal(t, 1, wrapped.calls)
	assert.Equal(t, 1, good.calls)
}

// errNoCredentialsf is a tiny helper used only in tests to build wrapped
// ErrNoCredentials values. Kept in the test file so production code stays clean.
func errNoCredentialsf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

func TestNewLayeredResolver_DefaultsWireDocumentedSourcesInOrder(t *testing.T) {
	r, ok := NewLayeredResolver().(*layeredResolver)
	require.True(t, ok, "NewLayeredResolver must return *layeredResolver for default wiring assertion")

	require.Len(t, r.sources, 2, "default wiring must compose vet env+file and DRY keychain")

	_, ok = r.sources[0].(*vetEnvFileSource)
	assert.True(t, ok, "first source must be vetEnvFileSource (env vars + vet-auth.yml)")

	_, ok = r.sources[1].(*dryKeychainSource)
	assert.True(t, ok, "second source must be dryKeychainSource (DRY keychain, no insecure fallback)")
}

func TestNewLayeredResolver_OptionAppendsCustomSource(t *testing.T) {
	custom := &stubSource{creds: Credentials{APIKey: "custom", TenantID: "ct"}}

	r, ok := NewLayeredResolver(WithSource(custom)).(*layeredResolver)
	require.True(t, ok)

	require.Len(t, r.sources, 3, "WithSource must append, not replace")
	assert.Same(t, custom, r.sources[2], "custom source must be appended after the defaults")
}

func TestVetEnvFileSource_NoCredentialsWhenBothEmpty(t *testing.T) {
	src := &vetEnvFileSource{
		apiKey:       func() string { return "" },
		tenantDomain: func() string { return "" },
	}

	_, err := src.resolve(context.Background())

	assert.ErrorIs(t, err, ErrNoCredentials)
}

func TestVetEnvFileSource_IncompleteWhenOnlyAPIKeyPresent(t *testing.T) {
	src := &vetEnvFileSource{
		apiKey:       func() string { return "k" },
		tenantDomain: func() string { return "" },
	}

	_, err := src.resolve(context.Background())

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIncompleteCredentials)
	assert.NotErrorIs(t, err, ErrNoCredentials, "partial credentials must stop the chain, not fall through")
	assert.Contains(t, err.Error(), "SAFEDEP_TENANT_ID")
}

func TestVetEnvFileSource_IncompleteWhenOnlyTenantPresent(t *testing.T) {
	src := &vetEnvFileSource{
		apiKey:       func() string { return "" },
		tenantDomain: func() string { return "t" },
	}

	_, err := src.resolve(context.Background())

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIncompleteCredentials)
	assert.NotErrorIs(t, err, ErrNoCredentials)
	assert.Contains(t, err.Error(), "SAFEDEP_API_KEY")
}

func TestVetEnvFileSource_ReturnsCredentialsWhenBothPresent(t *testing.T) {
	src := &vetEnvFileSource{
		apiKey:       func() string { return "k" },
		tenantDomain: func() string { return "t" },
	}

	got, err := src.resolve(context.Background())

	require.NoError(t, err)
	assert.Equal(t, Credentials{APIKey: "k", TenantID: "t"}, got)
}

// fakeKeychainResolver is a stub for cloud.CloseableCredentialResolver used to
// drive dryKeychainSource without touching the OS keychain.
type fakeKeychainResolver struct {
	creds *cloud.Credentials
	err   error
}

func (f *fakeKeychainResolver) Resolve() (*cloud.Credentials, error) {
	return f.creds, f.err
}

func (f *fakeKeychainResolver) Close() error { return nil }

func TestDryKeychainSource_ConstructionFailurePropagates(t *testing.T) {
	boom := errors.New("dbus unavailable")
	src := &dryKeychainSource{
		newResolver: func() (cloud.CloseableCredentialResolver, error) {
			return nil, boom
		},
	}

	_, err := src.resolve(context.Background())

	require.Error(t, err)
	assert.ErrorIs(t, err, boom, "real backend failures must propagate verbatim")
	assert.NotErrorIs(t, err, ErrNoCredentials, "construction failures are not 'no credentials'")
}

// On WSL/headless Linux the OS keyring backend is fundamentally
// unreachable. dry/keychain wraps the backend error with a stable
// "OS keychain unavailable" prefix; we treat that as ErrNoCredentials
// so the chain falls through to the env-vars hint.
func TestDryKeychainSource_BackendUnreachableFallsThrough(t *testing.T) {
	wrapped := fmt.Errorf("cloud: failed to create keychain: %w",
		fmt.Errorf("%s: %w", KeychainBackendUnavailableMarker,
			errors.New("name is not activatable")))
	src := &dryKeychainSource{
		newResolver: func() (cloud.CloseableCredentialResolver, error) {
			return nil, wrapped
		},
	}

	_, err := src.resolve(context.Background())

	assert.ErrorIs(t, err, ErrNoCredentials)
}

func TestDryKeychainSource_MissingCredentialsBecomesErrNoCredentials(t *testing.T) {
	src := &dryKeychainSource{
		newResolver: func() (cloud.CloseableCredentialResolver, error) {
			return &fakeKeychainResolver{
				err: fmt.Errorf("wrapped: %w", cloud.ErrMissingCredentials),
			}, nil
		},
	}

	_, err := src.resolve(context.Background())

	assert.ErrorIs(t, err, ErrNoCredentials)
}

func TestDryKeychainSource_ResolveErrorPropagates(t *testing.T) {
	boom := errors.New("keychain corrupted")
	src := &dryKeychainSource{
		newResolver: func() (cloud.CloseableCredentialResolver, error) {
			return &fakeKeychainResolver{err: boom}, nil
		},
	}

	_, err := src.resolve(context.Background())

	assert.ErrorIs(t, err, boom)
	assert.NotErrorIs(t, err, ErrNoCredentials)
}

func TestDryKeychainSource_SuccessReturnsCredentials(t *testing.T) {
	apiKeyCreds, cerr := cloud.NewAPIKeyCredential("kc-key", "kc-tenant")
	require.NoError(t, cerr)

	src := &dryKeychainSource{
		newResolver: func() (cloud.CloseableCredentialResolver, error) {
			return &fakeKeychainResolver{creds: apiKeyCreds}, nil
		},
	}

	got, err := src.resolve(context.Background())

	require.NoError(t, err)
	assert.Equal(t, Credentials{APIKey: "kc-key", TenantID: "kc-tenant"}, got)
}
