package app

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"
)

// SignalContext returns a context that the first SIGINT or SIGTERM cancels.
// The scan then saves its progress and exits with code 130. A second signal
// exits at once with code 130. The progress is still safe, because each
// batch commits in its own transaction (scan state design, section 2.2).
func SignalContext(parent context.Context) (context.Context, func()) {
	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	ctx, stop := watchSignals(parent, sigs, os.Exit)
	return ctx, func() {
		signal.Stop(sigs)
		stop()
	}
}

// Interrupted reports whether a signal canceled the context. Another cause,
// such as a stopped parent, is not an interrupt.
func Interrupted(ctx context.Context) bool { return errors.Is(context.Cause(ctx), ErrInterrupted) }

// watchSignals cancels the context on the first signal, with the cause
// ErrInterrupted, and calls exit on the second.
func watchSignals(parent context.Context, sigs <-chan os.Signal, exit func(int)) (context.Context, func()) {
	ctx, cancel := context.WithCancelCause(parent)
	done := make(chan struct{})
	go func() {
		select {
		case <-sigs:
			cancel(ErrInterrupted)
		case <-done:
			return
		}
		select {
		case <-sigs:
			exit(ExitInterrupted)
		case <-done:
		}
	}()
	var once bool
	return ctx, func() {
		if !once {
			once = true
			close(done)
		}
		cancel(nil)
	}
}
