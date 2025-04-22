package analytics

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsDisabled(t *testing.T) {
	t.Run("returns true if VET_DISABLE_TELEMETRY is set to true", func(t *testing.T) {
		os.Setenv(telemetryDisableEnvKey, "true")
		defer os.Unsetenv(telemetryDisableEnvKey)

		assert.True(t, IsDisabled())
	})

	t.Run("returns false if VET_DISABLE_TELEMETRY is not set", func(t *testing.T) {
		assert.False(t, IsDisabled())
	})
}

func TestCloseIsImmutable(t *testing.T) {
	Close()
	assert.Nil(t, globalPosthogClient)

	Close()
	assert.Nil(t, globalPosthogClient)
}
