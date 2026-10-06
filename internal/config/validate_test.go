package config

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateDefaults(t *testing.T) {
	l, err := Load(LoadOptions{LookupEnv: env(nil)})
	require.NoError(t, err)
	assert.NoError(t, l.Validate())
	assert.NoError(t, l.ValidateStrict())
}

func TestValidateRejects(t *testing.T) {
	cases := []struct {
		name string
		key  string
		raw  string
		want string
	}{
		{"mode", "output.mode", "fancy", `output.mode must be auto, rich, plain or agent, got "fancy" (flag)`},
		{"color", "output.color", "pink", `output.color must be auto, always or never, got "pink" (flag)`},
		{"concurrency", "scan.concurrency", "0", `scan.concurrency must be a number from 1 to 256, got "0" (flag)`},
		{"fail on", "policy.fail_on", "urgent", `policy.fail_on must be attacks, critical, high, medium, low or info, got "urgent" (flag)`},
		{"duration", "state.continue_within", "soon", `state.continue_within must be a duration such as 24h or 7d, got "soon" (flag)`},
		{"size", "state.retention.max_size", "big", `state.retention.max_size must be a size such as 500MB or 2GB, got "big" (flag)`},
		{"per target", "state.retention.per_target", "0", `state.retention.per_target must be 1 or more, got "0" (flag)`},
		{"url", "cloud.endpoints.api", "ftp://x", `cloud.endpoints.api must be an http or https URL, got "ftp://x" (flag)`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := Load(LoadOptions{LookupEnv: env(nil), Flags: map[string]string{tc.key: tc.raw}})
			require.NoError(t, err)
			err = l.Validate()
			assert.Equal(t, CodeInvalid, errCode(t, err))
			assert.Equal(t, tc.want, humanError(t, err))
		})
	}
}

func TestValidateNamesTheVariable(t *testing.T) {
	l, err := Load(LoadOptions{LookupEnv: env(map[string]string{"VET_OUTPUT_MODE": "fancy"})})
	require.NoError(t, err)
	assert.ErrorContains(t, l.Validate(), "(env VET_OUTPUT_MODE)")
}

func TestValidateStrictUnknownKey(t *testing.T) {
	user := writeFile(t, t.TempDir(), "config.yml", "scan:\n  inlcude_dev: true\n")
	l, err := Load(LoadOptions{UserFile: user, LookupEnv: env(nil)})
	require.NoError(t, err)
	assert.NoError(t, l.Validate(), "an unknown key is a warning for a normal run")

	err = l.ValidateStrict()
	assert.Equal(t, CodeUnknownKey, errCode(t, err))
	assert.ErrorContains(t, err, filepath.Base(user))
	assert.ErrorContains(t, err, "Did you mean scan.include_dev?")
}
