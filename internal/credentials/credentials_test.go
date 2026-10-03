package credentials

import (
	"errors"
	"fmt"
	"testing"

	"github.com/safedep/dry/cloud"
	"github.com/safedep/dry/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fixedResolver struct {
	creds *cloud.Credentials
	err   error
}

func (f fixedResolver) Resolve() (*cloud.Credentials, error) { return f.creds, f.err }

func TestResolve(t *testing.T) {
	key, err := cloud.NewAPIKeyCredential("sfd_key", "acme.safedep.io")
	require.NoError(t, err)

	cases := []struct {
		name      string
		resolver  fixedResolver
		anonymous bool
		tenant    string
		warning   bool
		code      string
	}{
		{"credentials", fixedResolver{creds: key}, false, "acme.safedep.io", false, ""},
		{"none is anonymous", fixedResolver{err: fmt.Errorf("%w: api_key", cloud.ErrMissingCredentials)}, true, "", false, ""},
		{"half is an error", fixedResolver{err: fmt.Errorf("%w: tenant missing", cloud.ErrIncompleteCredentials)}, false, "", false, CodeIncomplete},
		{"keychain failure is anonymous with a warning", fixedResolver{err: errors.New("dbus: no session bus")}, true, "", true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Resolve(Options{Resolver: tc.resolver})
			if tc.code != "" {
				require.Error(t, err)
				ue, ok := usefulerror.AsUsefulError(err)
				require.True(t, ok)
				assert.Equal(t, tc.code, ue.Code())
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.anonymous, res.Anonymous())
			assert.Equal(t, tc.tenant, res.TenantDomain())
			assert.Equal(t, tc.warning, res.Warning != "")
			if tc.anonymous {
				assert.Equal(t, "anonymous", res.Source())
			}
		})
	}
}

func TestResolveProfile(t *testing.T) {
	t.Setenv("SAFEDEP_PROFILE", "")
	res, err := Resolve(Options{Profile: "work", Resolver: fixedResolver{err: cloud.ErrMissingCredentials}})
	require.NoError(t, err)
	assert.Equal(t, "work", res.Profile)

	res, err = Resolve(Options{Resolver: fixedResolver{err: cloud.ErrMissingCredentials}})
	require.NoError(t, err)
	assert.Equal(t, "default", res.Profile)
}

func TestResolveFromEnvironment(t *testing.T) {
	t.Setenv("SAFEDEP_API_KEY", "sfd_env")
	t.Setenv("SAFEDEP_TENANT_ID", "env.safedep.io")
	res, err := Resolve(Options{})
	require.NoError(t, err)
	assert.False(t, res.Anonymous())
	assert.Equal(t, "env.safedep.io", res.TenantDomain())
	assert.Equal(t, "environment", res.Source())
}
