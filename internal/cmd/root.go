// Package cmd builds the vet command tree. Each top-level noun has its own
// package under internal/cmd. docs/DEVGUIDE.md holds the rules of the
// command shape.
package cmd

import (
	"context"
	"errors"

	"github.com/safedep/dry/usefulerror"
	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/cmd/config"
	"github.com/safedep/vet/v2/internal/cmd/doctor"
	"github.com/safedep/vet/v2/internal/cmd/fix"
	"github.com/safedep/vet/v2/internal/cmd/policy"
	"github.com/safedep/vet/v2/internal/cmd/report"
	"github.com/safedep/vet/v2/internal/cmd/scan"
	"github.com/safedep/vet/v2/internal/cmd/state"
	"github.com/safedep/vet/v2/internal/cmd/version"
)

// New builds the full command tree. main and the tests call it, so both
// walk the same tree.
func New(a *app.App) *cobra.Command {
	root := &cobra.Command{
		Use:   "vet",
		Short: "Find supply chain risk in code, artifacts and machines",
		Long: `vet finds supply chain risk in open source dependencies, GitHub Actions
workflows, container images and SBOMs. It checks each package for malware,
vulnerabilities and other risk, and applies your policy as a gate.

Run "vet scan" in a project directory to start.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return a.Apply()
		},
	}

	g := &a.Globals
	pf := root.PersistentFlags()
	pf.StringVarP(&g.Output, "output", "o", "", "Data format on stdout: table, plain, json, jsonl or a report format")
	pf.StringVar(&g.Mode, "mode", "", "Messaging mode on stderr: auto, rich, plain or agent")
	pf.BoolVarP(&g.Verbose, "verbose", "v", false, "Show more output on stderr")
	pf.BoolVarP(&g.Quiet, "quiet", "q", false, "Show only errors on stderr")
	pf.BoolVar(&g.NoInput, "no-input", false, "Never prompt")
	pf.StringVar(&g.ConfigFile, "config", "", "Config file to use in place of the user config file")
	pf.StringVar(&g.Profile, "profile", "", "SafeDep credential profile")

	root.AddCommand(
		config.New(a),
		doctor.New(a),
		fix.New(a),
		policy.New(a),
		report.New(a),
		scan.New(a),
		state.New(a),
		version.New(a),
	)

	return root
}

// runError marks an error that a command returned, so that Run can tell it
// from an error of cobra, which is always a usage error.
type runError struct{ err error }

func (e runError) Error() string { return e.err.Error() }
func (e runError) Unwrap() error { return e.err }

func markRunErrors(c *cobra.Command) {
	if run := c.RunE; run != nil {
		c.RunE = func(cmd *cobra.Command, args []string) error {
			if err := run(cmd, args); err != nil {
				return runError{err: err}
			}
			return nil
		}
	}
	for _, child := range c.Commands() {
		markRunErrors(child)
	}
}

// Run runs vet with the arguments. It returns the exit code, and the error
// to print or nil. A failed gate and a stop on a signal print no error,
// because the command already reported them.
func Run(ctx context.Context, args []string, o app.Options) (int, error) {
	return execute(ctx, New(app.New(o)), args)
}

func execute(ctx context.Context, root *cobra.Command, args []string) (int, error) {
	markRunErrors(root)
	root.SetArgs(args)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return app.ExitOK, nil
	}

	var re runError
	if !errors.As(err, &re) {
		if _, ok := usefulerror.AsUsefulError(err); !ok {
			err = app.UsageError(err.Error(), `Run "vet --help" to list the commands and the flags.`)
		}
	}
	code := app.ExitCode(err)
	if code == app.ExitGateFailed || code == app.ExitInterrupted {
		return code, nil
	}
	return code, err
}
