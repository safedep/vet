// Package tui provides a bubbletea-based terminal UI for live xBOM code scan
// progress. It displays real-time file scanning counters, signature match
// stats, and a styled summary with top signatures in boxed panels.
//
// The package is decoupled from the scanner via the EventSink type.
// Callers wire scanner callbacks to push events into the TUI.
package tui

import (
	"os"
	"sync/atomic"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/safedep/vet/pkg/code"
)

// Internal bubbletea messages.
type (
	fileScannedMsg struct{ filePath string }
	matchFoundMsg  struct {
		signatureID string
		tags        []string
		language    string
		filePath    string
	}
)
type scanDoneMsg struct{ err error }

// EventSink bridges scanner callbacks to the bubbletea program via an
// atomic pointer. All methods are goroutine-safe and fire-and-forget.
type EventSink struct {
	program atomic.Pointer[tea.Program]
}

func (s *EventSink) send(msg tea.Msg) {
	if p := s.program.Load(); p != nil {
		p.Send(msg)
	}
}

// FileScanned should be called for each file processed by the callgraph plugin.
func (s *EventSink) FileScanned(filePath string) {
	s.send(fileScannedMsg{filePath: filePath})
}

// MatchFound should be called for each individual signature match.
func (s *EventSink) MatchFound(data *code.SignatureMatchData) {
	s.send(matchFoundMsg{
		signatureID: data.SignatureID,
		tags:        data.Tags,
		language:    data.Language,
		filePath:    data.FilePath,
	})
}

// ScanDone should be called when the scan completes (with or without error).
func (s *EventSink) ScanDone(err error) {
	s.send(scanDoneMsg{err: err})
}

// IsTerminal reports whether stdout is connected to a terminal.
func IsTerminal() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}
