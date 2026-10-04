// Package spinner passes through dry/tui/spinner.
package spinner

import "github.com/safedep/dry/tui/spinner"

// Spinner shows that a step runs.
type Spinner = spinner.Spinner

// New returns a spinner with a label.
func New(label string) *Spinner { return spinner.New(label) }
