package state

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/config/appdir"
)

func TestPrepareDirs(t *testing.T) {
	root := t.TempDir()
	notADir := filepath.Join(root, "file")
	require.NoError(t, os.WriteFile(notADir, nil, 0o600))
	good := func(k string) string { return filepath.Join(root, k) }
	network := func(string) error { return errors.New("nfs") }

	cases := []struct {
		name      string
		state     string
		origin    string
		ephemeral bool
		checkFS   func(string) error
		wantCode  string
		wantEph   bool
		warning   bool
	}{
		{name: "writable directories", state: good("state"), origin: "flag"},
		{name: "ephemeral", state: good("state"), origin: "flag", ephemeral: true, wantEph: true},
		{name: "default directory fails", state: notADir, origin: "default", wantEph: true, warning: true},
		{name: "flag directory fails", state: notADir, origin: "flag", wantCode: CodeDirUnwritable},
		{name: "config directory fails", state: notADir, origin: "config", wantCode: CodeDirUnwritable},
		{name: "network file system", state: good("state2"), origin: "default", checkFS: network, wantCode: CodeDirNetworkFS},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			check := tc.checkFS
			if check == nil {
				check = func(string) error { return nil }
			}
			d, err := PrepareDirs(DirRequest{
				Dirs: appdir.Dirs{
					State: tc.state, Cache: good("cache"),
					Origin: map[appdir.Kind]string{appdir.State: tc.origin, appdir.Cache: "default"},
				},
				Ephemeral: tc.ephemeral,
				CheckFS:   check,
			})
			if tc.wantCode != "" {
				require.Error(t, err)
				var ue usefulerror.UsefulError
				require.ErrorAs(t, err, &ue)
				assert.Equal(t, tc.wantCode, ue.Code())
				return
			}
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, d.Close()) })
			assert.Equal(t, tc.wantEph, d.Ephemeral)
			assert.Equal(t, tc.warning, d.Warning != "")
			if !d.Ephemeral {
				assert.Equal(t, tc.state, d.State)
				return
			}
			s, err := Open(t.Context(), Options{StateDir: d.State, CacheDir: d.Cache})
			require.NoError(t, err)
			require.NoError(t, s.Close())
		})
	}
}

func TestEphemeralDirsRemoved(t *testing.T) {
	d, err := PrepareDirs(DirRequest{Ephemeral: true})
	require.NoError(t, err)
	require.NoError(t, appdir.Ensure(d.State))
	require.NoError(t, d.Close())
	_, err = os.Stat(d.State)
	assert.ErrorIs(t, err, os.ErrNotExist)
}

func TestCheckDir(t *testing.T) {
	assert.NoError(t, CheckDir(t.TempDir()))
}

func TestFlags(t *testing.T) {
	cases := []struct {
		name string
		args []string
		env  map[string]string
		want bool
	}{
		{name: "off"},
		{name: "flag", args: []string{"--ephemeral"}, want: true},
		{name: "env", env: map[string]string{EphemeralEnv: "1"}, want: true},
		{name: "env false", env: map[string]string{EphemeralEnv: "false"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var f Flags
			fs := pflag.NewFlagSet("t", pflag.ContinueOnError)
			f.Register(fs)
			require.NoError(t, fs.Parse(append(tc.args, "--state-dir", "/s")))
			assert.Equal(t, "/s", f.StateDir)
			assert.Equal(t, tc.want, f.EphemeralFrom(func(k string) (string, bool) { v, ok := tc.env[k]; return v, ok }))
		})
	}
}
