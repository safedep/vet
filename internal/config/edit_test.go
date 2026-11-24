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

// testPlugins are the plugins that the tests of this package know: two
// with a switch that is on, one that is off, and a report format.
var testPlugins = []Plugin{
	{Name: "dependency-cooldown", Switch: true, On: true},
	{Name: "codeusage", Switch: true, On: true},
	{Name: "tenant-policy", Switch: true},
	{Name: "table"},
}

// loadDefaults returns the defaults with testPlugins, for the edit methods.
func loadDefaults(t *testing.T) *Loaded {
	t.Helper()
	l, err := Load(LoadOptions{LookupEnv: env(nil), Plugins: testPlugins})
	require.NoError(t, err)
	return l
}

func TestSetInFileKeepsComments(t *testing.T) {
	ed := loadDefaults(t)
	p := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(p, []byte(userFile), 0o600))

	require.NoError(t, ed.SetInFile(p, "scan.concurrency", "16"))
	require.NoError(t, ed.SetInFile(p, "scan.include_dev", "true"))
	require.NoError(t, ed.SetInFile(p, "plugins.dependency-cooldown.options.days", "7"))
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	got := string(b)
	assert.Contains(t, got, "# my vet settings")
	assert.Contains(t, got, "concurrency: 16 # more is faster")
	assert.Contains(t, got, "include_dev: true")
	assert.Contains(t, got, "days: 7")

	l, err := Load(LoadOptions{ConfigFile: p, LookupEnv: env(nil), Plugins: testPlugins})
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
	ed := loadDefaults(t)
	p := filepath.Join(t.TempDir(), "sub", "config.yml")
	cases := []struct {
		key, value, code, text string
	}{
		{key: "scan.concurency", value: "4", code: CodeUnknownKey, text: "Did you mean scan.concurrency?"},
		{key: "scan.concurrency", value: "many", code: CodeInvalid, text: `scan.concurrency must be a whole number, got "many"`},
		{key: "scan.include_dev", value: "maybe", code: CodeInvalid, text: `scan.include_dev must be true or false, got "maybe"`},
		{key: "scan.concurrency", value: "x", code: CodeInvalid, text: "vet did not write the value to " + p},
		{key: "scan.concurrency", value: "0", code: CodeInvalid, text: "vet did not write the change to " + p},
		{key: "policy.fail_on", value: "severe", code: CodeInvalid, text: `policy.fail_on must be attacks, critical, high, medium, low or info, got "severe" (file ` + p + ")"},
		{key: "plugins.dependency-cooldwn.enabled", value: "false", code: CodeUnknownKey, text: "Did you mean plugins.dependency-cooldown.enabled?"},
		{key: "plugins.nosuch.enabled", value: "false", code: CodeUnknownKey, text: "vet config schema get lists the plugins."},
		{key: "plugins.table.enabled", value: "false", code: CodeUnknownKey, text: "table is a report format with no enabled key. The flags -o and --report select it."},
	}
	for _, tc := range cases {
		t.Run(tc.key+"="+tc.value, func(t *testing.T) {
			err := ed.SetInFile(p, tc.key, tc.value)
			assert.Equal(t, tc.code, errCode(t, err))
			assert.Contains(t, err.Error()+help(err), tc.text)
			assert.NotContains(t, err.Error()+help(err), ".tmp-", "the error names no temporary file")
			_, statErr := os.Stat(p)
			assert.ErrorIs(t, statErr, os.ErrNotExist, "a bad value writes no file")
			_, statErr = os.Stat(filepath.Dir(p))
			assert.ErrorIs(t, statErr, os.ErrNotExist, "vet checks a change before it writes a file or a folder")
		})
	}
	require.NoError(t, ed.SetInFile(p, "policy.fail_on", "low"), "a new file and its directory are made")
}

func TestDeleteInFile(t *testing.T) {
	ed := loadDefaults(t)
	p := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(p, []byte(userFile), 0o600))
	require.NoError(t, ed.DeleteInFile(p, "policy.fail_on"))
	b, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.NotContains(t, string(b), "policy", "an empty section goes")
	assert.Contains(t, string(b), "concurrency: 4")

	assert.Equal(t, CodeKeyNotSet, errCode(t, ed.DeleteInFile(p, "policy.fail_on")))
	assert.Equal(t, CodeUnknownKey, errCode(t, ed.DeleteInFile(p, "polcy.fail_on")))

	require.NoError(t, os.WriteFile(p, []byte("plugins:\n  nosuch:\n    enabled: false\n"), 0o600))
	require.NoError(t, ed.DeleteInFile(p, "plugins.nosuch.enabled"), "a user can delete an unknown key from the file")
}

func TestDeleteInFileWritesYAMLWhenEmpty(t *testing.T) {
	cases := []struct {
		name, file, want, afterSet string
	}{
		{name: "no comment", file: "scan:\n  concurrency: 4\n", want: "", afterSet: "scan:\n  concurrency: 2\n"},
		{
			name: "file comment", file: "# my vet settings\n\nscan:\n  concurrency: 4\n",
			want: "# my vet settings\n", afterSet: "# my vet settings\n\nscan:\n  concurrency: 2\n",
		},
	}
	ed := loadDefaults(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.yml")
			require.NoError(t, os.WriteFile(p, []byte(tc.file), 0o600))
			require.NoError(t, ed.DeleteInFile(p, "scan.concurrency"))
			b, err := os.ReadFile(p)
			require.NoError(t, err)
			assert.Equal(t, tc.want, string(b))
			require.NoError(t, ed.SetInFile(p, "scan.concurrency", "2"), "vet can edit the file again")
			b, err = os.ReadFile(p)
			require.NoError(t, err)
			assert.Equal(t, tc.afterSet, string(b))
		})
	}
}

func TestGet(t *testing.T) {
	l := loadDefaults(t)
	cases := []struct {
		key  string
		want any
		code string
	}{
		{key: "scan.concurrency", want: 8},
		{key: "policy.file", want: ""},
		{key: "plugins.codeusage.enabled", want: true},
		{key: "plugins.tenant-policy.enabled", want: false},
		{key: "plugins.codeusage.options.budget", want: nil},
		{key: "scan.nope", code: CodeUnknownKey},
		{key: "plugins.nosuch.enabled", code: CodeUnknownKey},
		{key: "plugins.table.enabled", code: CodeUnknownKey},
	}
	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			v, err := l.Get(tc.key)
			if tc.code != "" {
				assert.Equal(t, tc.code, errCode(t, err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, v)
		})
	}
}

func TestValuesListTheSwitchOfEachPlugin(t *testing.T) {
	dir := t.TempDir()
	user := writeFile(t, dir, "config.yml", "plugins:\n  codeusage:\n    enabled: false\n  cooldwn:\n    enabled: false\n  table:\n    enabled: true\n")
	l, err := Load(LoadOptions{UserFile: user, LookupEnv: env(nil), Plugins: testPlugins})
	require.NoError(t, err)
	vals, err := l.Values()
	require.NoError(t, err)
	assert.Equal(t, true, vals["plugins.dependency-cooldown.enabled"], "a plugin with no key shows its built-in state")
	assert.Equal(t, false, vals["plugins.tenant-policy.enabled"])
	assert.Equal(t, false, vals["plugins.codeusage.enabled"], "a layer wins over the built-in state")
	assert.Equal(t, Origin{Layer: LayerFile, Source: user}, l.Origins.Of("plugins.codeusage.enabled"))
	assert.NotContains(t, vals, "plugins.table.enabled", "a report format has no switch")
	assert.NotContains(t, vals, "plugins.cooldwn.enabled", "the effective config holds no unknown key")
	assert.Equal(t, []string{"plugins.cooldwn.enabled", "plugins.table.enabled"}, l.UnknownKeys)
	assert.Contains(t, SortedKeys(vals), "state.retention.per_target")
}

func help(err error) string {
	if ue, ok := usefulerror.AsUsefulError(err); ok {
		return ue.Help()
	}
	return ""
}
