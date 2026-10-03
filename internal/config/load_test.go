package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	return p
}

func env(vars map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := vars[k]
		return v, ok
	}
}

func trustAll(string) bool { return true }

func errCode(t *testing.T, err error) string {
	t.Helper()
	require.Error(t, err)
	ue, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok, "error is a usefulerror: %v", err)
	return ue.Code()
}

func humanError(t *testing.T, err error) string {
	t.Helper()
	require.Error(t, err)
	ue, ok := usefulerror.AsUsefulError(err)
	require.True(t, ok, "error is a usefulerror: %v", err)
	return ue.HumanError()
}

func TestLoadDefaults(t *testing.T) {
	l, err := Load(LoadOptions{LookupEnv: env(nil)})
	require.NoError(t, err)
	assert.Equal(t, Default().Scan.Concurrency, l.Config.Scan.Concurrency)
	assert.Equal(t, LayerDefault, l.Origins.Of("scan.concurrency").Layer)
	assert.Empty(t, l.File)
}

func TestLoadLayers(t *testing.T) {
	dir := t.TempDir()
	user := writeFile(t, dir, "config.yml", "scan:\n  concurrency: 4\n  include_dev: true\npolicy:\n  fail_on: high\n")

	l, err := Load(LoadOptions{
		UserFile:  user,
		LookupEnv: env(map[string]string{"VET_SCAN_CONCURRENCY": "6", "VET_SCAN_EXCLUDE": "a/**, b/**"}),
		Flags:     map[string]string{"policy.fail_on": "critical", "plugins.dependency-cooldown.options.days": "14"},
	})
	require.NoError(t, err)

	c := l.Config
	assert.True(t, c.Scan.IncludeDev)
	assert.Equal(t, 6, c.Scan.Concurrency)
	assert.Equal(t, []string{"a/**", "b/**"}, c.Scan.Exclude)
	assert.Equal(t, "critical", c.Policy.FailOn)
	assert.Equal(t, 14, c.PluginOptions("dependency-cooldown")["days"])

	assert.Equal(t, Origin{Layer: LayerFile, Source: user}, l.Origins.Of("scan.include_dev"))
	assert.Equal(t, Origin{Layer: LayerEnv, Source: "VET_SCAN_CONCURRENCY"}, l.Origins.Of("scan.concurrency"))
	assert.Equal(t, Origin{Layer: LayerFlag}, l.Origins.Of("policy.fail_on"))
	assert.Equal(t, LayerDefault, l.Origins.Of("output.mode").Layer)
}

func TestLoadFileChoice(t *testing.T) {
	dir := t.TempDir()
	managed := writeFile(t, dir, "managed.yml", "scan:\n  concurrency: 2\n")
	explicit := writeFile(t, dir, "explicit.yml", "scan:\n  concurrency: 3\n")
	user := writeFile(t, dir, "user.yml", "scan:\n  concurrency: 5\n")

	cases := []struct {
		name  string
		opts  LoadOptions
		want  int
		layer Layer
	}{
		{"managed wins", LoadOptions{ManagedFile: managed, ConfigFile: explicit, UserFile: user, TrustManaged: trustAll}, 2, LayerManaged},
		{"untrusted managed is ignored", LoadOptions{ManagedFile: managed, UserFile: user, TrustManaged: func(string) bool { return false }}, 5, LayerFile},
		{"config flag over user", LoadOptions{ConfigFile: explicit, UserFile: user}, 3, LayerFile},
		{"user file", LoadOptions{UserFile: user}, 5, LayerFile},
		{"missing user file is fine", LoadOptions{UserFile: filepath.Join(dir, "none.yml")}, 8, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.LookupEnv = env(nil)
			l, err := Load(tc.opts)
			require.NoError(t, err)
			assert.Equal(t, tc.want, l.Config.Scan.Concurrency)
			assert.Equal(t, tc.layer, l.FileLayer)
		})
	}
}

func TestLoadLockdown(t *testing.T) {
	dir := t.TempDir()
	managed := writeFile(t, dir, "managed.yml", "managed:\n  lockdown: true\npolicy:\n  fail_on: high\n")

	l, err := Load(LoadOptions{
		ManagedFile: managed, TrustManaged: trustAll,
		LookupEnv: env(map[string]string{"VET_POLICY_FAIL_ON": "low", "VET_SCAN_CONCURRENCY": "3"}),
	})
	require.NoError(t, err)
	assert.Equal(t, "high", l.Config.Policy.FailOn, "a variable cannot change a locked key")
	assert.Equal(t, 3, l.Config.Scan.Concurrency, "a key that the file does not set stays open")
	assert.NotEmpty(t, l.Warnings)

	_, err = Load(LoadOptions{
		ManagedFile: managed, TrustManaged: trustAll, LookupEnv: env(nil),
		Flags: map[string]string{"policy.fail_on": "low"},
	})
	assert.Equal(t, CodeLocked, errCode(t, err))

	assert.NoError(t, l.RefuseLocked("scan.strict", "scan.exclude"), "the managed file does not set them")
	assert.Equal(t, CodeLocked, errCode(t, l.RefuseLocked("scan.strict", "policy.fail_on")), "a local flag such as --fail-on")
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	bad := writeFile(t, dir, "bad.yml", "scan: [unclosed\n")
	wrongType := writeFile(t, dir, "type.yml", "scan:\n  concurrency: many\n")

	cases := []struct {
		name string
		opts LoadOptions
		code string
	}{
		{"missing --config", LoadOptions{ConfigFile: filepath.Join(dir, "none.yml")}, CodeFileMissing},
		{"bad yaml", LoadOptions{ConfigFile: bad}, CodeFileInvalid},
		{"wrong type in file", LoadOptions{ConfigFile: wrongType}, CodeInvalid},
		{"bad bool variable", LoadOptions{LookupEnv: env(map[string]string{"VET_SCAN_INCLUDE_DEV": "maybe"})}, CodeInvalid},
		{"unknown flag key", LoadOptions{Flags: map[string]string{"scan.inlcude_dev": "true"}}, CodeUnknownKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.opts.LookupEnv == nil {
				tc.opts.LookupEnv = env(nil)
			}
			_, err := Load(tc.opts)
			assert.Equal(t, tc.code, errCode(t, err))
		})
	}
}

func TestLoadNamesTheValueOfTheWrongType(t *testing.T) {
	dir := t.TempDir()
	cases := []struct{ file, want string }{
		{"scan:\n  concurrency: many\n", `scan.concurrency must be a whole number, got "many" (file %s)`},
		{"scan:\n  include_dev: maybe\n", `scan.include_dev must be true or false, got "maybe" (file %s)`},
	}
	for _, tc := range cases {
		path := writeFile(t, dir, "config.yml", tc.file)
		_, err := Load(LoadOptions{ConfigFile: path, LookupEnv: env(nil)})
		assert.Equal(t, fmt.Sprintf(tc.want, path), humanError(t, err))
	}
}

func TestLoadUnknownFileKeyWarns(t *testing.T) {
	dir := t.TempDir()
	user := writeFile(t, dir, "config.yml", "scan:\n  inlcude_dev: true\n")
	l, err := Load(LoadOptions{UserFile: user, LookupEnv: env(nil)})
	require.NoError(t, err)
	require.Len(t, l.Warnings, 1)
	assert.Contains(t, l.Warnings[0], "Did you mean scan.include_dev?")
}

func TestKeys(t *testing.T) {
	keys := Keys()
	assert.Contains(t, keys, "scan.include_dev")
	assert.Contains(t, keys, "state.retention.per_target")
	assert.Contains(t, keys, "cloud.endpoints.api")
	assert.True(t, IsKnownKey("plugins.x.enabled"))
	assert.True(t, IsKnownKey("plugins.x.options.days"))
	assert.False(t, IsKnownKey("plugins.x"))
	assert.False(t, IsKnownKey("plugins.x.other"))
	assert.Equal(t, "VET_SCAN_INCLUDE_DEV", EnvName("scan.include_dev"))
	assert.Equal(t, "VET_PLUGINS_DEPENDENCY_COOLDOWN_ENABLED", EnvName("plugins.dependency-cooldown.enabled"))
}

func TestPluginEnvKey(t *testing.T) {
	plugins := []string{"dependency-cooldown", "codeusage", "lockfile", "lockfile-extra"}
	cases := map[string]string{
		"VET_PLUGINS_DEPENDENCY_COOLDOWN_OPTIONS_DAYS":    "plugins.dependency-cooldown.options.days",
		"VET_PLUGINS_CODEUSAGE_ENABLED":                   "plugins.codeusage.enabled",
		"VET_PLUGINS_LOCKFILE_OPTIONS_TRUSTED_REGISTRIES": "plugins.lockfile.options.trusted_registries",
		"VET_PLUGINS_LOCKFILE_EXTRA_ENABLED":              "plugins.lockfile-extra.enabled",
		"VET_PLUGINS_UNKNOWN_ENABLED":                     "",
		"VET_PLUGINS_CODEUSAGE_OPTIONS_":                  "",
		"VET_PLUGINS_CODEUSAGE_COLOR":                     "",
		"VET_SCAN_STRICT":                                 "",
	}
	for name, want := range cases {
		key, ok := pluginEnvKey(name, plugins)
		assert.Equal(t, want != "", ok, name)
		assert.Equal(t, want, key, name)
	}
}

func TestLoadPluginVariables(t *testing.T) {
	dir := t.TempDir()
	managed := writeFile(t, dir, "managed.yml", "managed:\n  lockdown: true\nplugins:\n  codeusage:\n    enabled: false\n")
	l, err := Load(LoadOptions{
		ManagedFile: managed, TrustManaged: trustAll, LookupEnv: env(nil),
		Environ: func() []string {
			return []string{"VET_PLUGINS_DEPENDENCY_COOLDOWN_OPTIONS_DAYS=7", "VET_PLUGINS_CODEUSAGE_ENABLED=true", "HOME=/x"}
		},
		PluginNames: []string{"dependency-cooldown", "codeusage"},
	})
	require.NoError(t, err)
	assert.Equal(t, map[string]any{"days": 7}, l.Config.PluginOptions("dependency-cooldown"))
	assert.Equal(t, Origin{Layer: LayerEnv, Source: "VET_PLUGINS_DEPENDENCY_COOLDOWN_OPTIONS_DAYS"}, l.Origins.Of("plugins.dependency-cooldown.options.days"))
	assert.False(t, l.Config.PluginEnabled("codeusage", true), "a variable cannot change a locked key")
	assert.NotEmpty(t, l.Warnings)
}

func TestLoadWarnsThatTheManagedFileWins(t *testing.T) {
	dir := t.TempDir()
	managed := writeFile(t, dir, "managed.yml", "scan:\n  concurrency: 2\n")
	own := writeFile(t, dir, "own.yml", "scan:\n  concurrency: 9\n")
	l, err := Load(LoadOptions{ManagedFile: managed, ConfigFile: own, TrustManaged: trustAll, LookupEnv: env(nil)})
	require.NoError(t, err)
	assert.Equal(t, 2, l.Config.Scan.Concurrency)
	require.Len(t, l.Warnings, 1)
	assert.Contains(t, l.Warnings[0], "--config "+own+" is ignored")
}
