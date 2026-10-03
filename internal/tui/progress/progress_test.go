package progress

import (
	"bytes"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/assert"
)

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func start(w *syncBuffer, width int) *Bar {
	b := &Bar{w: w, width: width, label: "Checking 40 packages", total: 40, stop: make(chan struct{}), exited: make(chan struct{})}
	go b.animate()
	return b
}

func TestBarShowsTheCountAndClearsItsLine(t *testing.T) {
	cases := []struct {
		name  string
		width int
	}{
		{"wide", 80},
		{"narrow", 30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var w syncBuffer
			b := start(&w, tc.width)
			b.Set(12)
			assert.Eventually(t, func() bool { return strings.Contains(w.String(), "12/40") }, time.Second, 10*time.Millisecond)
			b.Stop()
			b.Stop()

			out := w.String()
			assert.True(t, strings.HasSuffix(out, "\r\033[K"), "Stop clears the line")
			for _, frame := range strings.Split(out, "\r\033[K") {
				assert.Less(t, ansi.StringWidth(frame), tc.width, "a frame fits the terminal")
				assert.NotContains(t, frame, "\n")
			}
		})
	}
}
