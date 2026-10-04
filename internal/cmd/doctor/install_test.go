package doctor

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/config"
)

func TestPathCheck(t *testing.T) {
	dir := t.TempDir()
	self, other := filepath.Join(dir, "vet"), filepath.Join(dir, "other-vet")
	for _, p := range []string{self, other} {
		require.NoError(t, os.WriteFile(p, nil, 0o700))
	}
	exe := func() (string, error) { return self, nil }
	cases := []struct {
		name string
		look func(string) (string, error)
		want Status
	}{
		{"this vet first", func(string) (string, error) { return self, nil }, Pass},
		{"another vet first", func(string) (string, error) { return other, nil }, Warn},
		{"not on PATH", func(string) (string, error) { return "", errors.New("not found") }, Warn},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, pathCheck(exe, tc.look).Status, tc.name)
	}
}

func TestPluginCheck(t *testing.T) {
	on := true
	cases := []struct {
		name    string
		plugins map[string]config.PluginConfig
		want    Status
	}{
		{"no section", nil, Pass},
		{"valid options", map[string]config.PluginConfig{"dependency-cooldown": {Options: map[string]any{"days": 3}}}, Pass},
		{"unknown plugin", map[string]config.PluginConfig{"my-org-check": {Enabled: &on}}, Warn},
		{"bad options", map[string]config.PluginConfig{"lockfile": {Options: map[string]any{"nope": 1}}}, Fail},
	}
	for _, tc := range cases {
		cfg := &config.Config{Plugins: tc.plugins}
		assert.Equal(t, tc.want, pluginCheck(cfg).Status, tc.name)
	}
}
