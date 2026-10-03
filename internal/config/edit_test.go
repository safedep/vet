package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const userFile = `# my vet settings
scan:
  concurrency: 4 # more is faster
policy:
  fail_on: high
`

func TestSetInFileKeepsComments(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(p, []byte(userFile), 0o600))

	require.NoError(t, SetInFile(p, "scan.concurrency", "16"))
	require.NoError(t, SetInFile(p, "scan.include_dev", "true"))
	require.NoError(t, SetInFile(p, "plugins.dependency-cooldown.options.days", "7"))
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	got := string(b)
	assert.Contains(t, got, "# my vet settings")
	assert.Contains(t, got, "concurrency: 16 # more is faster")
	assert.Contains(t, got, "include_dev: true")
	assert.Contains(t, got, "days: 7")

	l, err := Load(LoadOptions{ConfigFile: p, LookupEnv: func(string) (string, bool) { return "", false }})
	require.NoError(t, err)
	assert.Equal(t, 16, l.Config.Scan.Concurrency)
	assert.True(t, l.Config.Scan.IncludeDev)
	assert.Equal(t, 7, l.Config.PluginOptions("dependency-cooldown")["days"])
	info, err := os.Stat(p)
	require.NoError(t, err)
	if info.Mode().Perm() != 0o666 {
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	}
}

func TestSetInFileErrors(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "config.yml")
	cases := []struct {
		key, value, code, text string
	}{
		{key: "scan.concurency", value: "4", code: CodeUnknownKey, text: "Did you mean scan.concurrency?"},
		{key: "scan.concurrency", value: "many", code: CodeInvalid, text: `scan.concurrency must be a whole number, got "many"`},
		{key: "scan.include_dev", value: "maybe", code: CodeInvalid, text: `scan.include_dev must be true or false, got "maybe"`},
		{key: "scan.concurrency", value: "x", code: CodeInvalid, text: "vet did not write the value to " + p},
		{key: "scan.concurrency", value: "0", code: CodeInvalid, text: "vet did not write the change to " + p},
		{key: "policy.fail_on", value: "severe", code: CodeInvalid, text: `policy.fail_on must be critical, high, medium, low or info, got "severe" (file ` + p + ")"},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			err := SetInFile(p, tc.key, tc.value)
			assert.Equal(t, tc.code, errCode(t, err))
			assert.Contains(t, err.Error()+help(err), tc.text)
			_, statErr := os.Stat(p)
			assert.ErrorIs(t, statErr, os.ErrNotExist, "a bad value writes no file")
		})
	}
	require.NoError(t, SetInFile(p, "policy.fail_on", "low"), "a new file and its directory are made")
}

func TestDeleteInFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(p, []byte(userFile), 0o600))
	require.NoError(t, DeleteInFile(p, "policy.fail_on"))
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "policy", "an empty section goes")
	assert.Contains(t, string(b), "concurrency: 4")

	assert.Equal(t, CodeKeyNotSet, errCode(t, DeleteInFile(p, "policy.fail_on")))
	assert.Equal(t, CodeUnknownKey, errCode(t, DeleteInFile(p, "polcy.fail_on")))
}

func TestGet(t *testing.T) {
	c := Default()
	v, err := Get(&c, "scan.concurrency")
	require.NoError(t, err)
	assert.Equal(t, 8, v)
	v, err = Get(&c, "policy.file")
	require.NoError(t, err)
	assert.Equal(t, "", v)
	_, err = Get(&c, "scan.nope")
	assert.Equal(t, CodeUnknownKey, errCode(t, err))

	vals, err := Values(&c)
	require.NoError(t, err)
	assert.Contains(t, SortedKeys(vals), "state.retention.per_target")
}

func help(err error) string {
	if ue, ok := usefulerror.AsUsefulError(err); ok {
		return ue.Help()
	}
	return ""
}
