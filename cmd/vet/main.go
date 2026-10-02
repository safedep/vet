// Command vet finds supply chain risk in code, artifacts and machines.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/cmd"
	"github.com/safedep/vet/v2/internal/tui/errors"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code, err := cmd.Run(ctx, os.Args[1:], app.Options{})
	stop()
	if err != nil {
		errors.ExitWithCode(err, code)
	}
	os.Exit(code)
}
