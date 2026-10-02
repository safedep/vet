// Package humanize passes through dry/tui/humanize.
package humanize

import (
	"time"

	"github.com/safedep/dry/tui/humanize"
)

// Time returns a time relative to now, for example "4 minutes ago".
func Time(t, now time.Time) string { return humanize.Time(t, now) }

// Duration returns a short duration, for example "3m48s".
func Duration(d time.Duration) string { return humanize.Duration(d) }
