package auth

import (
	"os"
	"testing"
	"time"

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

func TestJWTExpiredToken(t *testing.T) {
	dummyAccessToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoxNzM3NDE3NjAwfQ.KaDtwFUNeTpEI8gN4Di72kdIVcr5ATc9pEyIXKWWrN8"
	prasedTime, _ := time.Parse(time.RFC3339Nano, "2025-06-04T17:53:11.353404581+05:30")
	globalConfig = &Config{
		CloudAccessTokenUpdatedAt: prasedTime,
		CloudAccessToken:          dummyAccessToken,
	}

	val, err := checkIfNewAccessTokenRequired()
	assert.Nil(t, err)
	assert.True(t, val)
}
