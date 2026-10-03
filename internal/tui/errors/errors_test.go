package errors

import (
	"bytes"
	stderrors "errors"
	"fmt"
	"testing"

	"github.com/safedep/dry/tui/output"
	"github.com/safedep/dry/usefulerror"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWriteAgent(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "useful error",
			err:  usefulerror.NewUsefulError().WithCode("usage_target").WithHumanError(`no target "x"`).WithHelp("Name a directory.").WithMsg("x"),
			want: `ERR: code=usage_target message="no target \"x\"" help="Name a directory."` + "\n",
		},
		{name: "plain error", err: stderrors.New("disk full\x1b[2J"), want: `ERR: code=unknown message="disk full\\x1b[2J" help=""` + "\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			require.NoError(t, WriteAgent(&b, tc.err))
			assert.Equal(t, tc.want, b.String())
		})
	}
}

func TestExitWithCodeInAgentMode(t *testing.T) {
	var stderr bytes.Buffer
	prev := output.CurrentMode()
	output.SetMode(output.Agent)
	output.SetWriters(&bytes.Buffer{}, &stderr)
	code := -1
	exit = func(c int) { code = c }
	t.Cleanup(func() {
		output.SetMode(prev)
		exit = nil
	})
	ExitWithCode(stderrors.New("boom"), 3)
	assert.Equal(t, 3, code)
	assert.Equal(t, `ERR: code=unknown message="boom" help=""`+"\n", stderr.String())
}

func TestWriteRich(t *testing.T) {
	cases := []struct {
		name      string
		err       error
		verbosity output.Verbosity
		want      string
	}{
		{
			name: "code after the message",
			err:  usefulerror.NewUsefulError().WithCode("usage_invalid").WithHumanError("unknown flag: --bogus").WithHelp(`Run "vet scan --help".`).WithMsg("x"),
			want: "✗ unknown flag: --bogus  [usage_invalid]\n› Run \"vet scan --help\".\n",
		},
		{
			name: "next lines are normal text with no padding",
			err:  usefulerror.NewUsefulError().WithCode("policy_invalid").WithHumanError("a.yml line 4: bad   \n\n  b.yml line 2: bad  \n").WithMsg("x"),
			want: "✗ a.yml line 4: bad  [policy_invalid]\n  b.yml line 2: bad\n",
		},
		{
			name: "no placeholder help",
			err:  usefulerror.NewUsefulError().WithCode("c").WithHumanError("m").WithHelp(noHelp).WithMsg("m"),
			want: "✗ m  [c]\n",
		},
		{
			name:      "verbose prints the cause but not the code and message again",
			err:       usefulerror.NewUsefulError().WithCode("c").WithHumanError("m").WithAdditionalHelp("more").WithMsg("m"),
			verbosity: output.Verbose,
			want:      "✗ m  [c]\n› more\n",
		},
		{
			name:      "verbose prints a wrapped cause",
			err:       usefulerror.NewUsefulError().WithCode("c").WithHumanError("m").Wrap(stderrors.New("rpc error")),
			verbosity: output.Verbose,
			want:      "✗ m  [c]\n  caused by: rpc error\n",
		},
		{name: "plain error has no code", err: stderrors.New("disk full"), want: "✗ disk full\n"},
		{
			name:      "plain error with -v prints the chain",
			err:       fmt.Errorf("save: %w", stderrors.New("disk full")),
			verbosity: output.Verbose,
			want:      "✗ save: disk full\n  caused by: disk full\n",
		},
	}
	prev := output.CurrentMode()
	t.Cleanup(func() {
		output.SetMode(prev)
		output.SetVerbosity(output.Normal)
	})
	output.SetMode(output.Rich)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := tc.verbosity
			if v == output.Silent {
				v = output.Normal
			}
			output.SetVerbosity(v)
			var b bytes.Buffer
			require.NoError(t, WriteRich(&b, tc.err))
			assert.Equal(t, tc.want, b.String())
		})
	}
}
