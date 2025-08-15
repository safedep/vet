package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func withGlobalConfig(t *testing.T, fn func() *Config) {
	oldConfig := globalConfig
	t.Cleanup(func() {
		globalConfig = oldConfig
	})

	globalConfig = fn()
}

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
		t.Setenv(communityServicesApiUrlEnvKey, "https://test.safedep.io")
		assert.Equal(t, "https://test.safedep.io", CommunityServicesApiUrl())
	})
}

func TestControlTowerUrl(t *testing.T) {
	assert.Equal(t, defaultControlPlaneApiUrl, ControlTowerUrl())

	t.Run("should return the env variable if set", func(t *testing.T) {
		t.Setenv(controlPlaneUrlEnvKey, "https://test.safedep.io")
		assert.Equal(t, "https://test.safedep.io", ControlTowerUrl())
	})
}

func TestDataPlaneUrl(t *testing.T) {
	assert.Equal(t, defaultDataPlaneApiUrl, DataPlaneUrl())

	t.Run("should return the env variable if set", func(t *testing.T) {
		t.Setenv(dataPlaneUrlEnvKey, "https://test.safedep.io")
		assert.Equal(t, "https://test.safedep.io", DataPlaneUrl())
	})
}

func TestSyncApiUrl(t *testing.T) {
	assert.Equal(t, defaultSyncApiUrl, SyncApiUrl())

	t.Run("should return the env variable if set", func(t *testing.T) {
		t.Setenv(syncUrlEnvKey, "https://test.safedep.io")
		assert.Equal(t, "https://test.safedep.io", SyncApiUrl())
	})
}

func TestInsightsApiV2Url(t *testing.T) {
	assert.Equal(t, defaultInsightsApiV2Url, InsightsApiV2Url())

	t.Run("should return the env variable if set", func(t *testing.T) {
		t.Setenv(apiV2UrlEnvKey, "https://test.safedep.io")
		assert.Equal(t, "https://test.safedep.io", InsightsApiV2Url())
	})
}

func TestTenantDomain(t *testing.T) {
	t.Run("should return the env variable if set", func(t *testing.T) {
		t.Setenv("VET_CONTROL_TOWER_TENANT_ID", "test-tenant")
		assert.Equal(t, "test-tenant", TenantDomain())
	})

	t.Run("should return env value when alternate env variable is set", func(t *testing.T) {
		t.Setenv("SAFEDEP_TENANT_ID", "test-tenant")
		assert.Equal(t, "test-tenant", TenantDomain())
	})

	t.Run("should fallback to default from global config", func(t *testing.T) {
		withGlobalConfig(t, func() *Config {
			return &Config{TenantDomain: "test-tenant-from-config"}
		})

		assert.Equal(t, "test-tenant-from-config", TenantDomain())
	})
}

func TestApiKey(t *testing.T) {
	t.Run("should return the env variable if set", func(t *testing.T) {
		t.Setenv("VET_API_KEY", "test-api-key")
		assert.Equal(t, "test-api-key", ApiKey())
	})

	t.Run("should return the env value when alternate env variable is set", func(t *testing.T) {
		t.Setenv("VET_INSIGHTS_API_KEY", "test-api-key-alt")
		assert.Equal(t, "test-api-key-alt", ApiKey())
	})

	t.Run("should return other alternate env variable if set", func(t *testing.T) {
		t.Setenv("SAFEDEP_API_KEY", "test-api-key-safe")
		assert.Equal(t, "test-api-key-safe", ApiKey())
	})

	t.Run("should fallback to default from global config", func(t *testing.T) {
		withGlobalConfig(t, func() *Config {
			return &Config{ApiKey: "test-api-key-from-config"}
		})

		assert.Equal(t, "test-api-key-from-config", ApiKey())
	})
}

func TestApiUrl(t *testing.T) {
	t.Run("should return the env variable if set", func(t *testing.T) {
		t.Setenv("VET_INSIGHTS_API_URL", "https://test-api.safedep.io")
		assert.Equal(t, "https://test-api.safedep.io", ApiUrl())
	})

	t.Run("should return community API URL when in community mode", func(t *testing.T) {
		t.Setenv("VET_COMMUNITY_MODE", "true")
		assert.Equal(t, defaultCommunityApiUrl, ApiUrl())
	})

	t.Run("should fallback to default from global config", func(t *testing.T) {
		withGlobalConfig(t, func() *Config {
			return &Config{ApiUrl: "https://test-api-from-config.safedep.io"}
		})

		assert.Equal(t, "https://test-api-from-config.safedep.io", ApiUrl())
	})

	t.Run("should return default API URL when no config is set", func(t *testing.T) {
		withGlobalConfig(t, func() *Config {
			return nil
		})

		assert.Equal(t, defaultApiUrl, ApiUrl())
	})
}

func TestCommunityMode(t *testing.T) {
	t.Run("should return true when env variable is set to true", func(t *testing.T) {
		t.Setenv("VET_COMMUNITY_MODE", "true")
		assert.True(t, CommunityMode())
	})

	t.Run("should return true when env variable is set to 1", func(t *testing.T) {
		t.Setenv("VET_COMMUNITY_MODE", "1")
		assert.True(t, CommunityMode())
	})

	t.Run("should return false when env variable is set to false", func(t *testing.T) {
		t.Setenv("VET_COMMUNITY_MODE", "false")
		assert.False(t, CommunityMode())
	})

	t.Run("should return false when env variable is set to invalid value", func(t *testing.T) {
		t.Setenv("VET_COMMUNITY_MODE", "invalid")
		assert.False(t, CommunityMode())
	})

	t.Run("should fallback to default from global config", func(t *testing.T) {
		withGlobalConfig(t, func() *Config {
			return &Config{Community: true}
		})

		assert.True(t, CommunityMode())
	})

	t.Run("should return false when no config is set", func(t *testing.T) {
		withGlobalConfig(t, func() *Config {
			return nil
		})

		assert.False(t, CommunityMode())
	})
}
