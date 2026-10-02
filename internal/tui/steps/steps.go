// Package steps passes through dry/tui/steps: the step counter "› [2/4]".
package steps

import "github.com/safedep/dry/tui/steps"

// Flow counts the steps of a command.
type Flow = steps.Flow

// New returns a flow of total steps.
func New(total int) *Flow { return steps.New(total) }
