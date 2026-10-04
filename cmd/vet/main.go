// Command vet finds supply chain risk in code, artifacts and machines.
package main

import (
	"context"
	"os"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/cmd"
	"github.com/safedep/vet/v2/internal/tui/errors"
)

func main() {
	ctx, stop := app.SignalContext(context.Background())
	code, err := cmd.Run(ctx, os.Args[1:], app.Options{})
	stop()
	if err != nil {
		errors.ExitWithCode(err, code)
	}
	os.Exit(code)
}
