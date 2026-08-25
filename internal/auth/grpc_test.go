package auth

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// assertValidServiceConfig confirms gRPC accepts the config. NewClient is lazy
// (it does not dial), but it parses the default service config eagerly and
// returns an error if the JSON is malformed.
func assertValidServiceConfig(t *testing.T, sc string) {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///test",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultServiceConfig(sc))
	require.NoError(t, err)
	require.NoError(t, conn.Close())
}

func TestCloudServiceConfigDefaults(t *testing.T) {
	t.Setenv(cloudGrpcMaxAttemptsEnvKey, "")
	t.Setenv(cloudGrpcTimeoutEnvKey, "")

	sc, ok := cloudServiceConfig()
	require.True(t, ok)

	// gRPC must accept the generated service config.
	assertValidServiceConfig(t, sc)

	var cfg struct {
		MethodConfig []struct {
			Timeout     string `json:"timeout"`
			RetryPolicy *struct {
				MaxAttempts          int      `json:"maxAttempts"`
				RetryableStatusCodes []string `json:"retryableStatusCodes"`
			} `json:"retryPolicy"`
		} `json:"methodConfig"`
	}
	require.NoError(t, json.Unmarshal([]byte(sc), &cfg))
	require.Len(t, cfg.MethodConfig, 1)

	mc := cfg.MethodConfig[0]
	assert.Equal(t, "30s", mc.Timeout)
	require.NotNil(t, mc.RetryPolicy)
	assert.Equal(t, defaultCloudGrpcMaxAttempts, mc.RetryPolicy.MaxAttempts)
	assert.Equal(t, []string{"UNAVAILABLE"}, mc.RetryPolicy.RetryableStatusCodes)
}

func TestCloudServiceConfigTimeoutOverride(t *testing.T) {
	t.Setenv(cloudGrpcTimeoutEnvKey, "1m30s")

	sc, ok := cloudServiceConfig()
	require.True(t, ok)
	assertValidServiceConfig(t, sc)
	assert.Contains(t, sc, `"timeout":"90s"`)
}

func TestCloudServiceConfigRetriesDisabled(t *testing.T) {
	t.Setenv(cloudGrpcMaxAttemptsEnvKey, "1")

	sc, ok := cloudServiceConfig()
	require.True(t, ok)
	assertValidServiceConfig(t, sc)
	assert.NotContains(t, sc, "retryPolicy")
	// Timeout is still applied.
	assert.Contains(t, sc, `"timeout":`)
}

func TestCloudServiceConfigFullyDisabled(t *testing.T) {
	t.Setenv(cloudGrpcMaxAttemptsEnvKey, "1")
	t.Setenv(cloudGrpcTimeoutEnvKey, "0s")

	_, ok := cloudServiceConfig()
	assert.False(t, ok)
}

func TestCloudGrpcMaxAttempts(t *testing.T) {
	cases := []struct {
		name string
		env  string
		want int
	}{
		{"unset", "", defaultCloudGrpcMaxAttempts},
		{"valid", "3", 3},
		{"clamped", "9", maxCloudGrpcMaxAttempts},
		{"invalid", "abc", defaultCloudGrpcMaxAttempts},
		{"below range", "0", defaultCloudGrpcMaxAttempts},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(cloudGrpcMaxAttemptsEnvKey, tc.env)
			assert.Equal(t, tc.want, cloudGrpcMaxAttempts())
		})
	}
}

func TestCloudGrpcTimeout(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		t.Setenv(cloudGrpcTimeoutEnvKey, "")
		assert.Equal(t, defaultCloudGrpcTimeout, cloudGrpcTimeout())
	})

	t.Run("invalid falls back", func(t *testing.T) {
		t.Setenv(cloudGrpcTimeoutEnvKey, "nope")
		assert.Equal(t, defaultCloudGrpcTimeout, cloudGrpcTimeout())
	})

	t.Run("zero disables", func(t *testing.T) {
		t.Setenv(cloudGrpcTimeoutEnvKey, "0s")
		assert.Equal(t, int64(0), int64(cloudGrpcTimeout()))
	})
}

func TestCloudDialOptions(t *testing.T) {
	assert.NotEmpty(t, cloudDialOptions())
}
