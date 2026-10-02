// Package prompt passes through dry/tui/prompt. A scan never prompts. Other
// commands prompt only in rich or plain mode without --no-input. In agent
// mode or with --no-input every prompt returns ErrAgentMode.
package prompt

import (
	"sync/atomic"

	"github.com/safedep/dry/tui/prompt"
)

var (
	ErrCancelled = prompt.ErrCancelled
	ErrAgentMode = prompt.ErrAgentMode
	ErrNoTTY     = prompt.ErrNoTTY
)

var noInput atomic.Bool

// SetNoInput turns prompts off, for --no-input.
func SetNoInput(v bool) { noInput.Store(v) }

// Confirm asks a yes or no question.
func Confirm(label string, defaultYes bool) (bool, error) {
	if noInput.Load() {
		return false, ErrAgentMode
	}
	return prompt.Confirm(label, defaultYes)
}

// Prompt asks for a line of text.
func Prompt(label string) (string, error) {
	if noInput.Load() {
		return "", ErrAgentMode
	}
	return prompt.Prompt(label)
}

// Select asks for one of the choices.
func Select(label string, choices []string) (string, error) {
	if noInput.Load() {
		return "", ErrAgentMode
	}
	return prompt.Select(label, choices)
}

// Secret asks for a secret and does not echo it.
func Secret(label string) (string, error) {
	if noInput.Load() {
		return "", ErrAgentMode
	}
	return prompt.Secret(label)
}
