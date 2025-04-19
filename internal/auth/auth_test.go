package auth

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, defaultCommunityServicesApiUrl, config.CommunityServicesApiUrl)
	assert.Equal(t, defaultControlPlaneApiUrl, config.ControlPlaneApiUrl)
	assert.Equal(t, defaultDataPlaneApiUrl, config.DataPlaneApiUrl)
	assert.Equal(t, defaultInsightsApiV2Url, config.InsightsApiV2Url)
	assert.Equal(t, defaultSyncApiUrl, config.SyncApiUrl)
}

func TestCommunityServicesApiUrl(t *testing.T) {
	assert.Equal(t, defaultCommunityServicesApiUrl, CommunityServicesApiUrl())

	t.Run("should return the env variable if set", func(t *testing.T) {
		os.Setenv(communityServicesApiUrlEnvKey, "https://test.safedep.io")
		assert.Equal(t, "https://test.safedep.io", CommunityServicesApiUrl())
	})
}

func TestControlTowerUrl(t *testing.T) {
	assert.Equal(t, defaultControlPlaneApiUrl, ControlTowerUrl())

	t.Run("should return the env variable if set", func(t *testing.T) {
		os.Setenv(controlPlaneUrlEnvKey, "https://test.safedep.io")
		assert.Equal(t, "https://test.safedep.io", ControlTowerUrl())
	})
}

func TestDataPlaneUrl(t *testing.T) {
	assert.Equal(t, defaultDataPlaneApiUrl, DataPlaneUrl())

	t.Run("should return the env variable if set", func(t *testing.T) {
		os.Setenv(dataPlaneUrlEnvKey, "https://test.safedep.io")
		assert.Equal(t, "https://test.safedep.io", DataPlaneUrl())
	})
}

func TestSyncApiUrl(t *testing.T) {
	assert.Equal(t, defaultSyncApiUrl, SyncApiUrl())

	t.Run("should return the env variable if set", func(t *testing.T) {
		os.Setenv(syncUrlEnvKey, "https://test.safedep.io")
		assert.Equal(t, "https://test.safedep.io", SyncApiUrl())
	})
}

func TestInsightsApiV2Url(t *testing.T) {
	assert.Equal(t, defaultInsightsApiV2Url, InsightsApiV2Url())

	t.Run("should return the env variable if set", func(t *testing.T) {
		os.Setenv(apiV2UrlEnvKey, "https://test.safedep.io")
		assert.Equal(t, "https://test.safedep.io", InsightsApiV2Url())
	})
}
