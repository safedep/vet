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
		{"mode", "output.mode", "fancy", "use auto, rich, plain or agent"},
		{"color", "output.color", "pink", "use auto, always or never"},
		{"concurrency", "scan.concurrency", "0", "use a number from 1 to 256"},
		{"fail on", "policy.fail_on", "urgent", "use critical, high, medium, low or info"},
		{"duration", "state.continue_within", "soon", "use a duration"},
		{"size", "state.retention.max_size", "big", "use a size"},
		{"per target", "state.retention.per_target", "0", "use 1 or more"},
		{"url", "cloud.endpoints.api", "ftp://x", "use an http or https URL"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := Load(LoadOptions{LookupEnv: env(nil), Flags: map[string]string{tc.key: tc.raw}})
			require.NoError(t, err)
			err = l.Validate()
			assert.Equal(t, CodeInvalid, errCode(t, err))
			assert.ErrorContains(t, err, tc.key)
			assert.ErrorContains(t, err, "from flag")
			assert.ErrorContains(t, err, tc.want)
		})
	}
}

func TestValidateNamesTheVariable(t *testing.T) {
	l, err := Load(LoadOptions{LookupEnv: env(map[string]string{"VET_OUTPUT_MODE": "fancy"})})
	require.NoError(t, err)
	assert.ErrorContains(t, l.Validate(), "from env VET_OUTPUT_MODE")
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
