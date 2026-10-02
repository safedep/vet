package appdir

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func env(vars map[string]string) Option {
	return WithLookupEnv(func(k string) (string, bool) {
		v, ok := vars[k]
		return v, ok
	})
}

func TestResolve(t *testing.T) {
	home := "/home/ada"
	cases := []struct {
		name   string
		opts   []Option
		kind   Kind
		want   string
		origin string
	}{
		{"linux default config", []Option{WithPlatform("linux", home, 1000, "/root"), env(nil)}, Config, "/home/ada/.config/safedep/vet", "default"},
		{"linux default state", []Option{WithPlatform("linux", home, 1000, "/root"), env(nil)}, State, "/home/ada/.local/state/safedep/vet", "default"},
		{"linux default cache", []Option{WithPlatform("linux", home, 1000, "/root"), env(nil)}, Cache, "/home/ada/.cache/safedep/vet", "default"},
		{"darwin cache", []Option{WithPlatform("darwin", home, 1000, "/var/root"), env(nil)}, Cache, "/home/ada/Library/Caches/safedep/vet", "default"},
		{"darwin config uses XDG layout", []Option{WithPlatform("darwin", home, 1000, "/var/root"), env(nil)}, Config, "/home/ada/.config/safedep/vet", "default"},
		{"xdg state", []Option{WithPlatform("linux", home, 1000, "/root"), env(map[string]string{"XDG_STATE_HOME": "/x/state"})}, State, "/x/state/safedep/vet", "env XDG_STATE_HOME"},
		{"relative xdg is ignored", []Option{WithPlatform("linux", home, 1000, "/root"), env(map[string]string{"XDG_CACHE_HOME": "rel"})}, Cache, "/home/ada/.cache/safedep/vet", "default"},
		{"sudo uses root", []Option{WithPlatform("linux", home, 0, "/root"), env(map[string]string{"SUDO_USER": "ada", "XDG_STATE_HOME": "/home/ada/.st"})}, State, "/root/.local/state/safedep/vet", "sudo"},
		{"config key", []Option{WithPlatform("linux", home, 1000, "/root"), env(nil), WithConfigKey(State, "/data/vet")}, State, "/data/vet", "config state.dir"},
		{"variable over config key", []Option{WithPlatform("linux", home, 1000, "/root"), env(map[string]string{"VET_STATE_DIR": "/v/state"}), WithConfigKey(State, "/data/vet")}, State, "/v/state", "env VET_STATE_DIR"},
		{"flag over variable", []Option{WithPlatform("linux", home, 1000, "/root"), env(map[string]string{"VET_CACHE_DIR": "/v/cache"}), WithOverride(Cache, "/f/cache")}, Cache, "/f/cache", "flag"},
		{"config key never sets config", []Option{WithPlatform("linux", home, 1000, "/root"), env(nil), WithConfigKey(Config, "/elsewhere")}, Config, "/home/ada/.config/safedep/vet", "default"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, err := Resolve("vet", tc.opts...)
			require.NoError(t, err)
			assert.Equal(t, filepath.FromSlash(tc.want), d.Get(tc.kind))
			assert.Equal(t, tc.origin, d.Origin[tc.kind])
		})
	}
}

func TestResolveWindows(t *testing.T) {
	d, err := Resolve("vet", WithPlatform("windows", `C:\Users\ada`, 1000, ""),
		env(map[string]string{"AppData": `C:\Users\ada\AppData\Roaming`, "LocalAppData": `C:\Users\ada\AppData\Local`, "ProgramData": `C:\ProgramData`}))
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(`C:\Users\ada\AppData\Roaming`, "safedep", "vet"), d.Config)
	assert.Equal(t, filepath.Join(`C:\Users\ada\AppData\Local`, "safedep", "vet", "state"), d.State)
	assert.Equal(t, filepath.Join(`C:\Users\ada\AppData\Local`, "safedep", "vet", "cache"), d.Cache)
	assert.Equal(t, filepath.Join(`C:\ProgramData`, "safedep", "vet"), d.Managed)
}

func TestManagedPaths(t *testing.T) {
	cases := map[string]string{
		"linux":  "/etc/safedep/vet",
		"darwin": "/Library/Application Support/safedep/vet",
	}
	for goos, want := range cases {
		d, err := Resolve("vet", WithPlatform(goos, "/h", 1000, "/root"), env(nil))
		require.NoError(t, err)
		assert.Equal(t, filepath.FromSlash(want), d.Managed, goos)
	}
}

func TestNoKindSharesADirectory(t *testing.T) {
	for _, goos := range []string{"linux", "darwin", "windows"} {
		d, err := Resolve("vet", WithPlatform(goos, "/h", 1000, "/root"), env(nil))
		require.NoError(t, err)
		dirs := []string{d.Config, d.State, d.Cache, d.Managed}
		for i := range dirs {
			for j := range dirs {
				if i == j {
					continue
				}
				assert.NotEqual(t, dirs[i], dirs[j], "%s: two kinds share a directory", goos)
				assert.False(t, strings.HasPrefix(dirs[j], dirs[i]+string(filepath.Separator)), "%s: %s is inside %s", goos, dirs[j], dirs[i])
			}
		}
	}
}

func TestEnsure(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a", "b")
	require.NoError(t, Ensure(p))
	st, err := os.Stat(p)
	require.NoError(t, err)
	assert.True(t, st.IsDir())
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0o700), st.Mode().Perm())
	}
	assert.Error(t, Ensure(""))
}
