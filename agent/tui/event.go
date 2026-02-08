// Package tui provides a lively terminal UI for watching agent execution
// in non-interactive mode. It displays real-time progress with animated
// spinners, tool call logging, elapsed time, and glamour-rendered results.
//
// The package is decoupled from the agent package via the EventSink interface.
// Callers wire their own agent execution and push events into the TUI.
package tui

import (
	"context"
	"os"

	"golang.org/x/term"
)

// EventSink receives events from agent execution and forwards them to the TUI.
// All methods are goroutine-safe and may be called from any goroutine.
type EventSink interface {
	// ToolCall reports that a tool was invoked with the given name and arguments.
	ToolCall(name, args string)

	// Status updates the current status message shown alongside the spinner.
	Status(msg string)

	// Result delivers the final output (typically markdown) for rendering.
	Result(content string)

	// Error reports a terminal error from the agent execution.
	Error(err error)
}

// ExecFunc is the function signature for the caller's agent execution logic.
// It receives a context and an EventSink to report progress. Returning an
// error causes the TUI to display an error state.
type ExecFunc func(ctx context.Context, sink EventSink) error

// Config controls the appearance and behavior of the TUI.
type Config struct {
	// Title is displayed in the header box (e.g. "ClawHub Skill Scanner").
	Title string

	// Subtitle is displayed below the title (e.g. "openai/gpt-4o (fast)").
	Subtitle string

	// MaxToolArgLength truncates tool argument display. Defaults to 80.
	MaxToolArgLength int
}

// IsTerminal reports whether stdin is connected to a terminal,
// indicating the TUI can be displayed.
func IsTerminal() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

func (c Config) maxArgLen() int {
	if c.MaxToolArgLength <= 0 {
		return 80
	}
	return c.MaxToolArgLength
}
