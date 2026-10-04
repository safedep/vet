// Package humanize passes through dry/tui/humanize.
package humanize

import (
	"fmt"
	"strconv"
	"time"

	"github.com/safedep/dry/tui/humanize"
)

// Time returns a time relative to now, for example "4 minutes ago".
func Time(t, now time.Time) string { return humanize.Time(t, now) }

// Duration returns a short duration, for example "3m48s".
func Duration(d time.Duration) string { return humanize.Duration(d) }

// Elapsed returns the run time of a step: "2.1s" below ten seconds, then
// "42s", "2m52s" and "1h5m".
func Elapsed(d time.Duration) string {
	if r := d.Round(100 * time.Millisecond); r < 10*time.Second {
		return fmt.Sprintf("%.1fs", r.Seconds())
	}
	if r := d.Round(time.Second); r < time.Hour {
		if r < time.Minute {
			return fmt.Sprintf("%ds", int(r.Seconds()))
		}
		return fmt.Sprintf("%dm%ds", int(r.Minutes()), int(r.Seconds())%60)
	}
	r := d.Round(time.Minute)
	return fmt.Sprintf("%dh%dm", int(r.Hours()), int(r.Minutes())%60)
}

// Count returns a count with its noun, as "1 scan" or "3 scans". The
// plural adds an s.
func Count(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}

// Bytes returns a size in SI units, for example "12.5 MB".
func Bytes(n int64) string {
	const unit = 1000
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "kMGTPE"[exp])
}
