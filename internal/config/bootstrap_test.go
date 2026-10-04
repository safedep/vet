package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/config/appdir"
)

type sandbox struct {
	home    string
	managed string
	vars    map[string]string
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	root := t.TempDir()
	s := &sandbox{home: filepath.Join(root, "home"), managed: filepath.Join(root, "etc"), vars: map[string]string{}}
	require.NoError(t, os.MkdirAll(filepath.Join(s.home, ".config", "safedep", "vet"), 0o700))
	require.NoError(t, os.MkdirAll(filepath.Join(s.managed, "safedep", "vet"), 0o755))
	return s
}

func (s *sandbox) opts(trust bool) BootstrapOptions {
	return BootstrapOptions{
		LookupEnv:    func(k string) (string, bool) { v, ok := s.vars[k]; return v, ok },
		TrustManaged: func(string) bool { return trust },
		DirOptions:   []appdir.Option{appdir.WithPlatform("linux", s.home, 1000, "/root")},
	}
}

func (s *sandbox) write(t *testing.T, path, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
}

func TestBootstrapUserFileSetsStateDir(t *testing.T) {
	s := newSandbox(t)
	s.write(t, filepath.Join(s.home, ".config", "safedep", "vet", "config.yml"), "state:\n  dir: /data/vet-state\n")

	rt, err := Bootstrap(s.opts(false))
	require.NoError(t, err)
	assert.Equal(t, "/data/vet-state", rt.Dirs.State)
	assert.Equal(t, "config state.dir", rt.Dirs.Origin[appdir.State])
	assert.Equal(t, filepath.Join(s.home, ".cache", "safedep", "vet"), rt.Dirs.Cache)
}

func TestBootstrapFlagsWinForDirs(t *testing.T) {
	s := newSandbox(t)
	o := s.opts(false)
	o.StateDir = "/flag/state"
	rt, err := Bootstrap(o)
	require.NoError(t, err)
	assert.Equal(t, "/flag/state", rt.Dirs.State)
}

func TestBootstrapManagedLockdown(t *testing.T) {
	s := newSandbox(t)

	managed := filepath.Join(s.managed, "safedep", "vet", "config.yml")
	s.write(t, managed, "managed:\n  lockdown: true\npolicy:\n  fail_on: high\n")
	s.write(t, filepath.Join(s.home, ".config", "safedep", "vet", "config.yml"), "policy:\n  fail_on: low\n")

	l, err := Load(LoadOptions{
		ManagedFile:  managed,
		UserFile:     filepath.Join(s.home, ".config", "safedep", "vet", "config.yml"),
		LookupEnv:    func(string) (string, bool) { return "", false },
		TrustManaged: func(string) bool { return true },
	})
	require.NoError(t, err)
	assert.Equal(t, "high", l.Config.Policy.FailOn, "the managed file replaces the user file")
	assert.Equal(t, LayerManaged, l.FileLayer)
	assert.True(t, l.Locked["policy.fail_on"])

	_, err = Load(LoadOptions{
		ManagedFile:  managed,
		LookupEnv:    func(string) (string, bool) { return "", false },
		TrustManaged: func(string) bool { return true },
		Flags:        map[string]string{"policy.fail_on": "low"},
	})
	assert.Equal(t, CodeLocked, errCode(t, err))
}

func TestManagedFileTrustedRejectsUserFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns every file it creates")
	}
	p := filepath.Join(t.TempDir(), "config.yml")
	require.NoError(t, os.WriteFile(p, []byte("x: 1\n"), 0o644))
	assert.False(t, ManagedFileTrusted(p))
}
