package cmd

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/tui/banner"
	"github.com/safedep/vet/v2/internal/tui/output"
)

func TestExecuteExitCodes(t *testing.T) {
	t.Cleanup(func() {
		output.SetMode(output.Rich)
		output.SetVerbosity(output.Normal)
	})
	cases := []struct {
		name     string
		args     []string
		runErr   error
		code     int
		printErr bool
	}{
		{name: "help", args: nil, code: app.ExitOK},
		{name: "ok", args: []string{"test", "run"}, code: app.ExitOK},
		{name: "unknown command", args: []string{"nope"}, code: app.ExitUsage, printErr: true},
		{name: "unknown flag", args: []string{"test", "run", "--nope"}, code: app.ExitUsage, printErr: true},
		{name: "bad args", args: []string{"test", "run", "extra"}, code: app.ExitUsage, printErr: true},
		{name: "verbose and quiet", args: []string{"test", "run", "-v", "-q"}, code: app.ExitUsage, printErr: true},
		{name: "runtime error", args: []string{"test", "run"}, runErr: errors.New("boom"), code: app.ExitRuntime, printErr: true},
		{name: "usage error from a command", args: []string{"test", "run"}, runErr: app.UsageError("bad target", "fix it"), code: app.ExitUsage, printErr: true},
		{name: "gate", args: []string{"test", "run"}, runErr: app.ErrGateFailed, code: app.ExitGateFailed},
		{name: "interrupted", args: []string{"test", "run"}, runErr: app.ErrInterrupted, code: app.ExitInterrupted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := New(app.New(app.Options{}))
			root.SetOut(&discard{})
			root.SetErr(&discard{})
			noun := &cobra.Command{Use: "test", Short: "t", Long: "t"}
			noun.AddCommand(&cobra.Command{
				Use: "run", Short: "t", Long: "t", Args: cobra.NoArgs,
				RunE: func(*cobra.Command, []string) error { return tc.runErr },
			})
			root.AddCommand(noun)

			code, err := execute(context.Background(), root, tc.args)
			assert.Equal(t, tc.code, code)
			if tc.printErr {
				require.Error(t, err)
				assert.Equal(t, tc.code, app.ExitCode(err))
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestHelpPrintsTheBanner(t *testing.T) {
	prev := output.CurrentMode()
	t.Cleanup(func() { output.SetMode(prev) })
	cases := []struct {
		name string
		mode output.Mode
		args []string
		want bool
	}{
		{name: "root", mode: output.Rich, args: []string{"--help"}, want: true},
		{name: "command", mode: output.Rich, args: []string{"scan", "-h"}, want: true},
		{name: "subcommand", mode: output.Rich, args: []string{"report", "show", "--help"}, want: true},
		{name: "command group", mode: output.Rich, args: []string{"report"}, want: true},
		{name: "help command", mode: output.Rich, args: []string{"help", "scan"}, want: true},
		{name: "plain mode", mode: output.Plain, args: []string{"scan", "-h"}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output.SetMode(tc.mode)
			root := New(app.New(app.Options{}))
			var out bytes.Buffer
			root.SetOut(&out)
			root.SetErr(&discard{})
			code, err := execute(context.Background(), root, tc.args)
			require.NoError(t, err)
			assert.Equal(t, app.ExitOK, code)
			assert.Equal(t, tc.want, strings.Contains(out.String(), banner.Tagline), out.String())
			assert.Contains(t, out.String(), "Usage:")
		})
	}
}
