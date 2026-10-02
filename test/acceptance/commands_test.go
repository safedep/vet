package acceptance

import (
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

// TestCommands runs the harness commands against the go tool, so it needs
// no vet binary.
func TestCommands(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "testdata/commands",
		Setup: func(env *testscript.Env) error {
			if err := Sandbox(env); err != nil {
				return err
			}
			return StartStub(env, "stub/fixtures")
		},
		Cmds:      Commands(),
		Condition: Condition,
	})
}
