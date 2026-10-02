package acceptance

import (
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

// TestCommands runs the harness commands against the go tool, so it needs
// no vet binary.
func TestCommands(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir:       "testdata/commands",
		Setup:     Sandbox,
		Cmds:      Commands(),
		Condition: Condition,
	})
}
