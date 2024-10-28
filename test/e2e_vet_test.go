package test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestE2EVet(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get current working directory: %v", err)
	}
	testscript.Run(t, testscript.Params{
		Dir:         "scripts/",
		WorkdirRoot: wd,
		Setup: func(env *testscript.Env) error {
			thisDir := env.WorkDir
			e2eRoot := filepath.Join(thisDir, "../../")
			e2eFixtures := filepath.Join(thisDir, "/fixtures")
			e2eVetBinary := filepath.Join(thisDir, "../vet")
			// Set these values as environment variables in the test environment
			env.Setenv("E2E_THIS_DIR", thisDir)
			env.Setenv("E2E_ROOT", e2eRoot)
			env.Setenv("E2E_FIXTURES", e2eFixtures)
			env.Setenv("E2E_VET_BINARY", e2eVetBinary)
			return nil
		},
	})
}
