package command

import (
	"os"

	"github.com/safedep/vet/internal/ui"
)

func FailOnError(stage string, err error) {
	if err != nil {
		ui.PrintError("%s failed due to error: %s", stage, err.Error())
		os.Exit(-1)
	}
}
