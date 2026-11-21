package view

import (
	"fmt"
	"path"
	"sync"
	"time"

	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/humanize"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/progress"
	"github.com/safedep/vet/v2/internal/tui/style"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// beatEvery is how often a view with no live line prints the progress of a
// long stage. A CI log then shows that the scan runs.
const beatEvery = 15 * time.Second

// The kinds of live line.
const (
	lineStatus = "status"
	lineBar    = "bar"
)

// snapshot is what a stage does now.
type snapshot struct {
	kind    report.ScanKind
	stage   string
	started time.Time
	done    int
	total   int
	dir     string
	work    plugin.Work
}

// waits reports an enrich stage that waits for the long work of an
// enricher. The count of the stage does not move then.
func (s snapshot) waits() bool {
	return s.stage == engine.StageEnrich && s.work.Name != "" && !s.work.Done
}

// text says what the stage does now, for the live line and the heartbeat.
// It is empty for a stage with nothing to say.
func (s snapshot) text(now time.Time) string {
	switch {
	case s.waits():
		t := s.work.Label + ": " + humanize.Elapsed(now.Sub(s.work.Started))
		if s.work.Budget > 0 {
			t += " of the " + humanize.Elapsed(s.work.Budget) + " budget"
		}
		if s.total > 0 {
			t += fmt.Sprintf(" · %d of %s checked", s.done, plural(s.total, "package"))
		}
		return t
	case s.stage == engine.StageExtract:
		what := "Reading the manifests"
		if s.kind == report.ScanKindEndpoint {
			what = "Reading the tools on this machine"
		}
		t := fmt.Sprintf("%s: %s in %s", what, plural(s.done, "file"), humanize.Elapsed(now.Sub(s.started)))
		if s.dir != "" {
			t += " · " + escape.Line(s.dir)
		}
		return t
	case s.stage == engine.StageEnrich && s.total > 0:
		return fmt.Sprintf("Checking %s: %d done in %s", plural(s.total, "package"), s.done, humanize.Elapsed(now.Sub(s.started)))
	case s.stage == engine.StageEvaluate && s.total > 0:
		return fmt.Sprintf("Evaluating the controls: %d of %s in %s", s.done, plural(s.total, "manifest"), humanize.Elapsed(now.Sub(s.started)))
	}
	return ""
}

// lineKind is the live line for the snapshot: a status line while the walk
// runs or while the enrich stage waits, a bar while it checks packages.
func (s snapshot) lineKind() string {
	switch {
	case s.waits(), s.stage == engine.StageExtract:
		return lineStatus
	case s.stage == engine.StageEnrich && s.total > 0:
		return lineBar
	}
	return ""
}

// shown is the snapshot that the live line reads. It has its own lock,
// because the line redraws from its own goroutine, and Stop waits for that
// goroutine while the view holds its lock.
type shown struct {
	mu sync.Mutex
	s  snapshot
}

func (sh *shown) set(s snapshot) {
	sh.mu.Lock()
	sh.s = s
	sh.mu.Unlock()
}

func (sh *shown) text(now time.Time) string {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.s.text(now)
}

// Walk records the folder of the file that the extract stage reads.
func (v *Scan) Walk(rel string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.stage != engine.StageExtract {
		return
	}
	dir := path.Dir(rel)
	if dir == "." {
		dir = ""
	}
	if dir == v.dir {
		return
	}
	v.dir = dir
	v.update()
}

// Work records the long work of an enricher. A report that ends other work
// than the current work changes nothing.
func (v *Scan) Work(w plugin.Work) {
	v.mu.Lock()
	defer v.mu.Unlock()
	switch {
	case !w.Done:
		v.work = w
	case w.Name == v.work.Name:
		v.work = plugin.Work{}
	default:
		return
	}
	v.update()
}

func (v *Scan) snapshot() snapshot {
	return snapshot{kind: v.o.Kind, stage: v.stage, started: v.started, done: v.done, total: v.total, dir: v.dir, work: v.work}
}

// update publishes the state of the stage and draws the live line that it
// needs. The caller holds mu.
func (v *Scan) update() {
	s := v.snapshot()
	v.shown.set(s)
	if !v.live() {
		return
	}
	kind := s.lineKind()
	if kind != v.lineKind {
		v.stopBar()
		switch kind {
		case lineStatus:
			v.bar = progress.StartStatus(func() string { return v.shown.text(v.now()) })
		case lineBar:
			v.bar = progress.Start("Checking "+plural(s.total, "package"), s.total)
		}
		v.lineKind = kind
	}
	if kind == lineBar {
		v.bar.Set(s.done)
	}
}

// startBeat starts the heartbeat of a view with no live line. The caller
// holds mu.
func (v *Scan) startBeat() {
	if v.beatStop != nil || v.beatEnded || v.live() || v.o.Saved {
		return
	}
	stop := make(chan struct{})
	v.beatStop = stop
	go func() {
		t := time.NewTicker(beatEvery)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				v.beat()
			}
		}
	}()
}

// stopBeat ends the heartbeat for good. The caller holds mu. It does not
// wait for the goroutine, which needs mu to print: beat prints nothing once
// the view has no stage.
func (v *Scan) stopBeat() {
	if v.beatStop != nil {
		close(v.beatStop)
		v.beatStop = nil
	}
	v.beatEnded = true
}

// beat prints the progress of a stage that has run for beatEvery or more.
// A tick that fires just before Stop prints nothing.
func (v *Scan) beat() {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	if v.beatEnded || v.stage == "" || now.Sub(v.started) < beatEvery {
		return
	}
	s := v.snapshot()
	text := s.text(now)
	if text == "" {
		return
	}
	switch v.mode {
	case output.Agent:
		line := fmt.Sprintf("progress: %s %d", v.stage, v.done)
		if s.waits() {
			line += " work=" + field(s.work.Name)
		}
		v.line(line)
	case output.Plain:
		v.line("[INFO] " + text)
	default:
		v.line(style.Faint("› ") + text)
	}
}
