package cmd

import (
	"context"
	"testing"

	"github.com/safedep/dry/usefulerror"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/tui/output"
)

func TestCobraUsageErrors(t *testing.T) {
	t.Cleanup(func() {
		output.SetMode(output.Rich)
		output.SetVerbosity(output.Normal)
	})
	cases := []struct {
		name string
		args []string
		msg  string
		help string
	}{
		{
			name: "unknown command suggests the full command",
			args: []string{"tst"},
			msg:  `unknown command "tst" for "vet"`,
			help: `Did you mean vet test? Run "vet --help" to list the commands and the flags.`,
		},
		{
			name: "unknown command with no suggestion",
			args: []string{"zzzzzz"},
			msg:  `unknown command "zzzzzz" for "vet"`,
			help: `Run "vet --help" to list the commands and the flags.`,
		},
		{
			name: "unknown subcommand suggests the full command",
			args: []string{"test", "shwo"},
			msg:  `unknown command "shwo" for "vet test"`,
			help: `Did you mean vet test show? Run "vet test --help" to list the commands and the flags.`,
		},
		{
			name: "unknown subcommand with no suggestion",
			args: []string{"test", "zzzzzz"},
			msg:  `unknown command "zzzzzz" for "vet test"`,
			help: `Run "vet test --help" to list the commands and the flags.`,
		},
		{
			name: "unknown flag names the help of the failing command",
			args: []string{"test", "run", "--bogus"},
			msg:  "unknown flag: --bogus",
			help: `Run "vet test run --help" to see the arguments and the flags.`,
		},
		{name: "no argument", args: []string{"test", "run", "extra"}, msg: `vet test run takes no argument, got "extra"`},
		{name: "missing argument", args: []string{"test", "show"}, msg: "vet test show needs 1 argument: ID"},
		{name: "missing arguments", args: []string{"test", "set"}, msg: "vet test set needs 2 arguments: KEY VALUE"},
		{name: "extra argument", args: []string{"test", "show", "a", "b"}, msg: "vet test show takes 1 argument (ID), got 2"},
		{name: "at most", args: []string{"test", "scan", "a", "b"}, msg: "vet test scan takes at most 1 argument (TARGET), got 2"},
		{name: "at least", args: []string{"test", "add"}, msg: "vet test add needs at least 2 arguments: A B"},
		{name: "range", args: []string{"test", "diff"}, msg: "vet test diff takes 1 to 2 arguments (BASE HEAD), got 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := New(app.New(app.Options{}))
			root.SetOut(&discard{})
			root.SetErr(&discard{})
			noun := &cobra.Command{Use: "test", Short: "t", Long: "t"}
			run := func(*cobra.Command, []string) error { return nil }
			noun.AddCommand(
				&cobra.Command{Use: "run", Args: cobra.NoArgs, RunE: run},
				&cobra.Command{Use: "show ID", Args: cobra.ExactArgs(1), RunE: run},
				&cobra.Command{Use: "set KEY VALUE", Args: cobra.ExactArgs(2), RunE: run},
				&cobra.Command{Use: "scan [TARGET]", Args: cobra.MaximumNArgs(1), RunE: run},
				&cobra.Command{Use: "add A B", Args: cobra.MinimumNArgs(2), RunE: run},
				&cobra.Command{Use: "diff BASE [HEAD]", Args: cobra.RangeArgs(1, 2), RunE: run},
			)
			root.AddCommand(noun)

			code, err := execute(context.Background(), root, tc.args)
			assert.Equal(t, app.ExitUsage, code)
			ue, ok := usefulerror.AsUsefulError(err)
			require.True(t, ok)
			assert.Equal(t, app.CodeUsage, ue.Code())
			assert.Equal(t, tc.msg, ue.HumanError())
			help := tc.help
			if help == "" {
				help = `Run "vet ` + tc.args[0] + " " + tc.args[1] + ` --help" to see the arguments and the flags.`
			}
			assert.Equal(t, help, ue.Help())
		})
	}
}

func TestArgNames(t *testing.T) {
	cases := map[string]string{
		"show ID":            "ID",
		"set KEY VALUE":      "KEY VALUE",
		"scan [TARGET]":      "TARGET",
		"diff [BASE [HEAD]]": "BASE HEAD",
		"version":            "",
	}
	for use, want := range cases {
		assert.Equal(t, want, argNames(use), use)
	}
}
