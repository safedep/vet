package version

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/config/appdir"
	"github.com/safedep/vet/v2/internal/tui/output"
)

func TestInfoLine(t *testing.T) {
	cases := []struct {
		name string
		info Info
		want string
	}{
		{
			name: "release",
			info: Info{Version: "v2.0.1", Commit: "8957dc6e71302384a6ddc8d", Go: "go1.26.3", Platform: "linux/amd64"},
			want: "vet v2.0.1 (8957dc6) go1.26.3 linux/amd64",
		},
		{
			name: "pseudo-version names the commit once",
			info: Info{Version: "v2.0.0-20261003111228-8957dc6e7130", Commit: "8957dc6e71302384a6ddc8d", Go: "go1.26.3", Platform: "linux/amd64"},
			want: "vet dev (8957dc6) go1.26.3 linux/amd64",
		},
		{
			name: "no commit",
			info: Info{Version: "devel", Go: "go1.26.3", Platform: "darwin/arm64"},
			want: "vet devel go1.26.3 darwin/arm64",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.info.Line())
		})
	}
}

func TestVersion(t *testing.T) {
	t.Cleanup(func() {
		output.SetWriters(os.Stdout, os.Stderr)
		output.SetMode(output.Rich)
	})
	output.SetMode(output.Plain)
	cases := []struct {
		name   string
		format string
		check  func(t *testing.T, out string)
	}{
		{name: "json", format: "json", check: func(t *testing.T, out string) {
			var i Info
			require.NoError(t, json.Unmarshal([]byte(out), &i))
			assert.Equal(t, Current(), i)
		}},
		{name: "plain", format: "plain", check: func(t *testing.T, out string) {
			assert.Equal(t, Current().Line()+"\n", out)
		}},
		{name: "table", format: "table", check: func(t *testing.T, out string) {
			assert.Equal(t, Current().Line()+"\n", out)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			output.SetWriters(&stdout, &stderr)
			a := app.New(app.Options{})
			a.Globals.Output = tc.format
			c := New(a)
			c.SetArgs(nil)
			require.NoError(t, c.Execute())
			tc.check(t, stdout.String())
			assert.Empty(t, stderr.String())
		})
	}
}

func TestVersionModeObeysALockedConfig(t *testing.T) {
	t.Cleanup(func() {
		output.SetWriters(os.Stdout, os.Stderr)
		output.SetMode(output.Rich)
	})
	root := t.TempDir()
	managed := filepath.Join(root, "safedep", "vet")
	require.NoError(t, os.MkdirAll(managed, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(managed, "config.yml"), []byte("managed:\n  lockdown: true\noutput:\n  mode: plain\n"), 0o600))
	env := map[string]string{"ProgramData": root}
	a := app.New(app.Options{
		LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
		Bootstrap: config.BootstrapOptions{
			TrustManaged: func(string) bool { return true },
			DirOptions:   []appdir.Option{appdir.WithPlatform("windows", t.TempDir(), 1000, "")},
		},
	})
	a.Globals.Mode = "agent"
	output.SetWriters(&bytes.Buffer{}, &bytes.Buffer{})
	c := New(a)
	c.SetArgs(nil)
	err := c.Execute()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "output.mode is locked")
}
