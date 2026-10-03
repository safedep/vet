package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui/output"
)

func TestLockableKeys(t *testing.T) {
	cases := []struct {
		name string
		o    Options
		want []string
	}{
		{"no flag", Options{}, nil},
		{"gate", Options{FailOn: "high", Policy: "p.yml"}, []string{"policy.fail_on", "policy.file"}},
		{
			"scan flags",
			Options{Strict: true, Exclude: []string{"docs"}, CooldownDays: 7},
			[]string{"scan.strict", "scan.exclude", "plugins.dependency-cooldown.options.days"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.o.lockableKeys())
		})
	}
}

func TestOutcome(t *testing.T) {
	cases := []struct {
		name              string
		renderErr, runErr error
		want              int
	}{
		{"clean", nil, nil, app.ExitOK},
		{"gate", app.ErrGateFailed, nil, app.ExitGateFailed},
		{"strict", nil, engine.ErrStrict, app.ExitRuntime},
		{"strict and gate", app.ErrGateFailed, engine.ErrStrict, app.ExitRuntime},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := outcome(tc.renderErr, tc.runErr)
			assert.Equal(t, tc.want, app.ExitCode(err))
			if tc.runErr != nil {
				assert.ErrorContains(t, err, CodeStrict, "the strict message prints")
			}
		})
	}
}

func TestRetentionSkipsAStoppedScan(t *testing.T) {
	root := t.TempDir()
	store, err := state.Open(context.Background(), state.Options{StateDir: filepath.Join(root, "state")})
	require.NoError(t, err)
	cache, err := state.OpenCache(context.Background(), filepath.Join(root, "cache"))
	require.NoError(t, err)
	require.NoError(t, store.Close())
	require.NoError(t, cache.Close())

	var stderr bytes.Buffer
	prev := output.CurrentMode()
	output.SetMode(output.Plain)
	output.SetWriters(os.Stdout, &stderr)
	t.Cleanup(func() {
		output.SetMode(prev)
		output.SetWriters(os.Stdout, os.Stderr)
	})

	cases := []struct {
		name    string
		stopped bool
		warns   bool
	}{
		{"stopped", true, false},
		{"completed", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stderr.Reset()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if tc.stopped {
				cancel()
			}
			cfg := config.Default()
			applyRetention(ctx, &cfg, store, cache)
			if tc.warns {
				assert.Contains(t, stderr.String(), "retention:", "a closed store fails, so the test sees that retention ran")
				return
			}
			assert.Empty(t, stderr.String())
		})
	}
}
