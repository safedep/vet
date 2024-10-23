package test

import (
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestE2EVet(t *testing.T) {
	testscript.Run(t, testscript.Params{
		Dir: "scenarios/scripts",
		Setup: func(env *testscript.Env) error {
			// Set the environment variables
			env.Setenv("E2E_VET_BINARY", "")
			env.Setenv("E2E_ROOT", "")
			return nil
		},
	})
}
