// Package prompt passes through dry/tui/prompt. A scan never prompts. Other
// commands prompt only in rich mode without --no-input.
package prompt

import "github.com/safedep/dry/tui/prompt"

var (
	ErrCancelled = prompt.ErrCancelled
	ErrAgentMode = prompt.ErrAgentMode
	ErrNoTTY     = prompt.ErrNoTTY
)

// Confirm asks a yes or no question.
func Confirm(label string, defaultYes bool) (bool, error) { return prompt.Confirm(label, defaultYes) }

// Prompt asks for a line of text.
func Prompt(label string) (string, error) { return prompt.Prompt(label) }

// Select asks for one of the choices.
func Select(label string, choices []string) (string, error) { return prompt.Select(label, choices) }

// Secret asks for a secret and does not echo it.
func Secret(label string) (string, error) { return prompt.Secret(label) }
