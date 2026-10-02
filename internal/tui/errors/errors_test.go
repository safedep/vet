package errors

import (
	"bytes"
	stderrors "errors"
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
