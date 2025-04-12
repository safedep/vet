package registry

import (
	"testing"

	packagev1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/package/v1"
	"github.com/safedep/dry/adapters"
	"github.com/stretchr/testify/assert"
)

// Just a sanity check. The adapters have their own tests.
func TestPackageVersionResolver(t *testing.T) {
	gh, err := adapters.NewGithubClient(adapters.DefaultGitHubClientConfig())
	assert.NoError(t, err)
	assert.NotNil(t, gh)

	pvr, err := NewPackageVersionResolver(gh)

	assert.NoError(t, err)
	assert.NotNil(t, pvr)

	version, err := pvr.ResolvePackageLatestVersion(packagev1.Ecosystem_ECOSYSTEM_NPM, "react")
	assert.NoError(t, err)
	assert.NotNil(t, version)
}

func TestPackageVersionResolver_Error(t *testing.T) {
	gh, err := adapters.NewGithubClient(adapters.DefaultGitHubClientConfig())
	assert.NoError(t, err)
	assert.NotNil(t, gh)

	t.Run("nil github client", func(t *testing.T) {
		pvr, err := NewPackageVersionResolver(nil)
		assert.Error(t, err)
		assert.Nil(t, pvr)
	})

	t.Run("invalid ecosystem", func(t *testing.T) {
		pvr, err := NewPackageVersionResolver(gh)
		assert.NoError(t, err)
		assert.NotNil(t, pvr)

		version, err := pvr.ResolvePackageLatestVersion(packagev1.Ecosystem_ECOSYSTEM_UNSPECIFIED, "react")
		assert.Error(t, err)
		assert.Empty(t, version)
	})

	t.Run("invalid package name", func(t *testing.T) {
		pvr, err := NewPackageVersionResolver(gh)
		assert.NoError(t, err)
		assert.NotNil(t, pvr)

		version, err := pvr.ResolvePackageLatestVersion(packagev1.Ecosystem_ECOSYSTEM_NPM, "does-not-exist")
		assert.Error(t, err)
		assert.Empty(t, version)
	})
}
