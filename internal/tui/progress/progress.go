// Package progress draws one live progress line on stderr. The caller
// prints the outcome of the work in its place, so no progress line stays
// on the terminal after Stop.
package progress

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/safedep/dry/tui/meter"
	"github.com/safedep/dry/tui/output"
	"github.com/safedep/dry/tui/style"
)

const interval = 100 * time.Millisecond

var frames = []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}

// Bar is a live line with a label, a bar and a done/total count. The
// caller starts it only for a terminal in rich mode.
type Bar struct {
	w     io.Writer
	width int

	mu    sync.Mutex
	label string
	done  int
	total int

	stop   chan struct{}
	exited chan struct{}
	once   sync.Once
}

// Start draws the bar and redraws it until Stop.
func Start(label string, total int) *Bar {
	b := &Bar{
		w: output.Stderr(), width: output.Width(), label: label, total: total,
		stop: make(chan struct{}), exited: make(chan struct{}),
	}
	go b.animate()
	return b
}

// Set records the units done.
func (b *Bar) Set(done int) {
	b.mu.Lock()
	b.done = done
	b.mu.Unlock()
}

// Stop ends the animation and clears the line.
func (b *Bar) Stop() {
	b.once.Do(func() {
		close(b.stop)
		<-b.exited
		b.draw("")
	})
}

func (b *Bar) animate() {
	defer close(b.exited)
	t := time.NewTicker(interval)
	defer t.Stop()
	for i := 0; ; i++ {
		b.draw(b.line(frames[i%len(frames)]))
		select {
		case <-b.stop:
			return
		case <-t.C:
		}
	}
}

// line renders one frame. A line that does not fit the terminal drops the
// bar, because a wrapped line breaks the redraw.
func (b *Bar) line(frame rune) string {
	b.mu.Lock()
	label, done, total := b.label, b.done, b.total
	b.mu.Unlock()
	count := fmt.Sprintf("%d/%d", done, total)
	s := string(frame) + " " + meter.Render(meter.Bar{Label: label, Value: int64(done), Max: int64(total), ValueText: count})
	if ansi.StringWidth(s) < b.width {
		return s
	}
	return ansi.Truncate(fmt.Sprintf("%c %s %s", frame, label, style.Faint(count)), b.width-1, "")
}

// draw replaces the current line. Carriage return and erase line are the
// only way to redraw a line in place.
func (b *Bar) draw(s string) {
	if _, err := fmt.Fprint(b.w, "\r\033[K"+s); err != nil {
		return
	}
}
