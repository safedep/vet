// Package progress passes through dry/tui/progress.
package progress

import "github.com/safedep/dry/tui/progress"

// Progress draws one or more progress bars on stderr.
type Progress = progress.Progress

// Tracker is one progress bar.
type Tracker = progress.Tracker

// New returns a progress display.
func New() *Progress { return progress.New() }
