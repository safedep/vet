package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/config/appdir"
)

func TestIsPolicyName(t *testing.T) {
	for name, want := range map[string]bool{
		"default": true, "strict": true, "": false, "vet-policy.yml": false, "p.YAML": false, "dir/p": false, `dir\p`: false,
	} {
		assert.Equal(t, want, IsPolicyName(name), name)
	}
}

func TestResolvePolicy(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)
	require.NoError(t, os.WriteFile("local", []byte("version: 2\n"), 0o600))
	rt := &Runtime{Dirs: appdir.Dirs{Config: filepath.Join(cwd, "cfg")}}
	cases := []struct {
		in, want string
	}{
		{in: "", want: ""},
		{in: "default", want: filepath.Join(cwd, "cfg", "policies", "default.yml")},
		{in: "local", want: "local"},
		{in: "vet-policy.yml", want: "vet-policy.yml"},
		{in: "dir/strict", want: "dir/strict"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			assert.Equal(t, tc.want, rt.ResolvePolicy(tc.in))
		})
	}
}
