package grpcdial

import (
	"testing"

	"github.com/safedep/dry/cloud"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/credentials"
	"github.com/safedep/vet/v2/test/acceptance/stub"
)

// TestCloud guards the credential that each SafeDep Cloud call sends. A
// workload credential has no fixed API key, and it sends its own tenant
// header, so the endpoint carries no API key and no tenant.
func TestCloud(t *testing.T) {
	key, err := cloud.NewAPIKeyCredential("sfd_key", "acme.safedep.io")
	require.NoError(t, err)
	ep, err := Cloud("https://api.safedep.io", &credentials.Result{Credentials: key})
	require.NoError(t, err)
	assert.Equal(t, Endpoint{URL: "https://api.safedep.io", APIKey: "sfd_key", Tenant: "acme.safedep.io"}, ep)

	s, err := stub.Start(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	s.SetWorkloadEnv(t, "acme.safedep.io")
	res, err := credentials.Resolve(credentials.Options{})
	require.NoError(t, err)
	ep, err = Cloud("https://api.safedep.io", res)
	require.NoError(t, err)
	assert.Equal(t, "https://api.safedep.io", ep.URL)
	assert.Empty(t, ep.APIKey)
	assert.Empty(t, ep.Tenant)
	assert.NotNil(t, ep.Workload)
}
