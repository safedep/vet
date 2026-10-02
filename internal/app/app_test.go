package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/config"
	"github.com/safedep/vet/v2/internal/config/appdir"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/printer"
	"github.com/safedep/vet/v2/internal/tui/prompt"
)

func TestExitCode(t *testing.T) {
	coded := func(code string) error {
		return usefulerror.NewUsefulError().WithCode(code).WithHumanError("x").WithMsg("x")
	}
	cases := []struct {
		name string
		err  error
		want int
	}{
		{name: "nil", want: ExitOK},
		{name: "gate", err: fmt.Errorf("scan: %w", ErrGateFailed), want: ExitGateFailed},
		{name: "interrupted", err: ErrInterrupted, want: ExitInterrupted},
		{name: "context canceled", err: context.Canceled, want: ExitInterrupted},
		{name: "usage", err: UsageError("bad", "help"), want: ExitUsage},
		{name: "config", err: coded(config.CodeUnknownKey), want: ExitUsage},
		{name: "state dir", err: coded("state_dir_unwritable"), want: ExitUsage},
		{name: "credentials", err: coded("credentials_incomplete"), want: ExitUsage},
		{name: "wrapped usage", err: fmt.Errorf("load: %w", coded("config_invalid")), want: ExitUsage},
		{name: "other usefulerror", err: coded("localdb_open_failure"), want: ExitRuntime},
		{name: "plain error", err: errors.New("boom"), want: ExitRuntime},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, ExitCode(tc.err))
		})
	}
}

func TestApply(t *testing.T) {
	t.Cleanup(func() {
		output.SetMode(output.Rich)
		output.SetVerbosity(output.Normal)
	})
	cases := []struct {
		name      string
		g         Globals
		wantErr   bool
		mode      output.Mode
		verbosity output.Verbosity
	}{
		{name: "verbose and quiet", g: Globals{Verbose: true, Quiet: true}, wantErr: true},
		{name: "bad mode", g: Globals{Mode: "loud"}, wantErr: true},
		{name: "agent mode", g: Globals{Mode: "agent"}, mode: output.Agent, verbosity: output.Normal},
		{name: "plain quiet", g: Globals{Mode: "plain", Quiet: true}, mode: output.Plain, verbosity: output.Silent},
		{name: "rich verbose", g: Globals{Mode: "rich", Verbose: true}, mode: output.Rich, verbosity: output.Verbose},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := New(Options{})
			a.Globals = tc.g
			err := a.Apply()
			if tc.wantErr {
				assert.Equal(t, ExitUsage, ExitCode(err))
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.mode, output.CurrentMode())
			assert.Equal(t, tc.verbosity, output.CurrentVerbosity())
		})
	}
}

func TestPrinter(t *testing.T) {
	t.Cleanup(func() { output.SetMode(output.Rich) })
	output.SetMode(output.Agent)

	a := New(Options{})
	p, err := a.Printer()
	require.NoError(t, err)
	assert.Equal(t, printer.JSON, p.Format())

	a.Globals.Output = "plain"
	p, err = a.Printer()
	require.NoError(t, err)
	assert.Equal(t, printer.Plain, p.Format())

	a.Globals.Output = "xml"
	_, err = a.Printer()
	assert.Equal(t, ExitUsage, ExitCode(err))
}

func TestConfig(t *testing.T) {
	t.Cleanup(func() { output.SetMode(output.Rich) })
	home := t.TempDir()
	dir := filepath.Join(home, ".config", "safedep", "vet")
	require.NoError(t, os.MkdirAll(dir, 0o700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yml"), []byte("output:\n  mode: plain\n"), 0o600))
	env := map[string]string{}
	newApp := func() *App {
		return New(Options{
			LookupEnv: func(k string) (string, bool) { v, ok := env[k]; return v, ok },
			Bootstrap: config.BootstrapOptions{
				TrustManaged: func(string) bool { return false },
				DirOptions:   []appdir.Option{appdir.WithPlatform("linux", home, 1000, "/root")},
			},
		})
	}

	a := newApp()
	a.Globals.Profile = "work"
	rt, err := a.Config(ConfigOptions{StateDir: "/s"})
	require.NoError(t, err)
	assert.Equal(t, "work", rt.Config.Cloud.Profile)
	assert.Equal(t, "/s", rt.Dirs.State)
	assert.Equal(t, output.Plain, output.CurrentMode(), "the config mode applies without --mode")

	again, err := a.Config(ConfigOptions{})
	require.NoError(t, err)
	assert.Same(t, rt, again)

	output.SetMode(output.Rich)
	a = newApp()
	a.Globals.Mode = "agent"
	require.NoError(t, a.Apply())
	_, err = a.Config(ConfigOptions{})
	require.NoError(t, err)
	assert.Equal(t, output.Agent, output.CurrentMode(), "--mode wins over the config")

	env["VET_OUTPUT_MODE"] = "loud"
	_, err = newApp().Config(ConfigOptions{})
	assert.Equal(t, ExitUsage, ExitCode(err))
}

func TestApplyNoInputRefusesPrompts(t *testing.T) {
	a := New(Options{LookupEnv: func(string) (string, bool) { return "", false }})
	a.Globals.NoInput = true
	require.NoError(t, a.Apply())
	t.Cleanup(func() { prompt.SetNoInput(false) })
	_, err := prompt.Confirm("continue?", true)
	assert.ErrorIs(t, err, prompt.ErrAgentMode)
}

func TestConfirmNamesTheFlag(t *testing.T) {
	a := New(Options{LookupEnv: func(string) (string, bool) { return "", false }})
	a.Globals.NoInput = true
	require.NoError(t, a.Apply())
	t.Cleanup(func() { prompt.SetNoInput(false) })
	ok, err := a.Confirm("Delete 3 scans?", "--yes")
	assert.False(t, ok)
	ue, isUseful := usefulerror.AsUsefulError(err)
	require.True(t, isUseful)
	assert.Equal(t, CodeNeedsConfirmation, ue.Code())
	assert.Contains(t, ue.Help(), "--yes")
	assert.Equal(t, ExitUsage, ExitCode(err))
}
