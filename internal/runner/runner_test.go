package runner

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/plugins/sinks/plain"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/view"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
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

func TestRenderPrintsTheReportStepBeforeTheReport(t *testing.T) {
	var term bytes.Buffer
	prev := output.CurrentMode()
	output.SetMode(output.Plain)
	output.SetWriters(&term, &term)
	t.Cleanup(func() {
		output.SetMode(prev)
		output.SetWriters(os.Stdout, os.Stderr)
	})
	sink, err := plain.New(plugin.MapConfig(nil))
	require.NoError(t, err)
	v := view.NewScan(view.Options{Target: "."})
	v.Stage(engine.StageReport, 4, 4)

	require.NoError(t, Render(context.Background(), plugintest.SampleReport(), v, []engine.Output{{Format: plain.Name, Sink: sink}}))

	step := strings.Index(term.String(), "[INFO] Report\n")
	require.GreaterOrEqual(t, step, 0, term.String())
	assert.Equal(t, 0, step, "the step line comes before the report:\n%s", term.String())
}
