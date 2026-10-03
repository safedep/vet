package app

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatchSignals(t *testing.T) {
	sigs := make(chan os.Signal, 2)
	exited := make(chan int, 1)
	ctx, stop := watchSignals(context.Background(), sigs, func(code int) { exited <- code })
	defer stop()

	sigs <- os.Interrupt
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		require.Fail(t, "the first signal must cancel the context")
	}
	select {
	case <-exited:
		require.Fail(t, "the first signal must not exit")
	case <-time.After(20 * time.Millisecond):
	}

	sigs <- os.Interrupt
	select {
	case code := <-exited:
		assert.Equal(t, ExitInterrupted, code)
	case <-time.After(time.Second):
		require.Fail(t, "the second signal must exit")
	}
}

func TestWatchSignalsStop(t *testing.T) {
	sigs := make(chan os.Signal, 1)
	ctx, stop := watchSignals(context.Background(), sigs, func(int) { t.Error("no exit after stop") })
	stop()
	stop()
	assert.Error(t, ctx.Err())
}
