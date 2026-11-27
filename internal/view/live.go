package view

import (
	"fmt"
	"path"
	"slices"
	"sync"
	"time"

	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/glyph"
	"github.com/safedep/vet/v2/internal/tui/humanize"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/progress"
	"github.com/safedep/vet/v2/internal/tui/style"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// beatEvery is how often a view with no live line prints the progress of a
// long stage. A CI log then shows that the scan runs. The heartbeat checks
// the time each beatTick, so the first line comes beatEvery after the stage
// starts.
const (
	beatEvery = 15 * time.Second
	beatTick  = time.Second
)

// The kinds of live line.
const (
	lineStatus = "status"
	lineBar    = "bar"
)

// liveLine is the line that redraws in place on a terminal.
type liveLine interface {
	Set(done int)
	Stop()
}

// startLine draws a live line of a kind. A bar counts the packages of the
// enrich stage. A status line reads its text on each frame.
func startLine(kind string, total int, status func() string) liveLine {
	if kind == lineBar {
		return progress.Start("Checking "+plural(total, "package"), total)
	}
	return progress.StartStatus(status)
}

// newTicker returns the ticks of the heartbeat and the function that stops
// them.
func newTicker() (<-chan time.Time, func()) {
	t := time.NewTicker(beatTick)
	return t.C, t.Stop
}

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
	return s.stage == engine.StageEnrich && s.work.Name != ""
}

// text says what the stage does now, for the live line and the heartbeat.
// It is empty for a stage with nothing to say. g joins the facts of the
// line.
func (s snapshot) text(now time.Time, g glyph.Set) string {
	elapsed := humanize.Elapsed(now.Sub(s.started))
	switch {
	case s.waits():
		t := s.work.Label + ": " + humanize.Elapsed(now.Sub(s.work.Started))
		if s.work.Budget > 0 {
			t += " of the " + budgetText(s.work.Budget) + " budget"
		}
		if s.total > 0 {
			t += fmt.Sprintf("%s%d of %s checked", g.Sep, s.done, plural(s.total, "package"))
		}
		return t
	case s.stage == engine.StageExtract:
		t := "Reading the manifests"
		if s.kind == report.ScanKindEndpoint {
			t = "Reading the tools on this machine"
		}
		// A pull request scan reads its base, and an endpoint audit lists
		// its tools, before the first file counts.
		if s.done > 0 {
			t += ": " + plural(s.done, "file")
		}
		t += " in " + elapsed
		if s.dir != "" {
			t += g.Sep + escape.Line(s.dir)
		}
		return t
	case s.stage == engine.StageEnrich && s.total > 0:
		return fmt.Sprintf("Checking %s: %d done in %s", plural(s.total, "package"), s.done, elapsed)
	case s.stage == engine.StageEnrich:
		// The enrichers prepare before the first package counts.
		return "Checking the packages in " + elapsed
	case s.stage == engine.StageEvaluate && s.total > 0:
		return fmt.Sprintf("Evaluating the controls: %d of %s in %s", s.done, plural(s.total, "manifest"), elapsed)
	}
	return ""
}

// budgetText gives a budget of whole minutes as "5m", and any other budget
// as a run time.
func budgetText(d time.Duration) string {
	if d >= time.Minute && d%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return humanize.Elapsed(d)
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

func (sh *shown) text(now time.Time, g glyph.Set) string {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	return sh.s.text(now, g)
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

// Work records the long work of an enricher. Two enrichers can work at the
// same time. The view shows the work that started first.
func (v *Scan) Work(w plugin.Work) {
	v.mu.Lock()
	defer v.mu.Unlock()
	i := slices.IndexFunc(v.works, func(o plugin.Work) bool { return o.Name == w.Name })
	switch {
	case w.Done && i < 0:
		return
	case w.Done:
		v.works = slices.Delete(v.works, i, i+1)
	case i < 0:
		v.works = append(v.works, w)
	default:
		v.works[i] = w
	}
	v.update()
}

func (v *Scan) snapshot() snapshot {
	s := snapshot{kind: v.o.Kind, stage: v.stage, started: v.started, done: v.done, total: v.total, dir: v.dir}
	if len(v.works) > 0 {
		s.work = slices.MinFunc(v.works, func(a, b plugin.Work) int { return a.Started.Compare(b.Started) })
	}
	return s
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
		if kind != "" {
			v.bar = v.startLine(kind, s.total, func() string { return v.shown.text(v.now(), v.glyphs) })
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
	ticks, stopTicks := v.ticker()
	go func() {
		defer stopTicks()
		for {
			select {
			case <-stop:
				return
			case <-ticks:
				v.beat()
			}
		}
	}()
}

// stopBeat ends the heartbeat for good. The caller holds mu. It does not
// wait for the goroutine, which needs mu to print: beat prints nothing once
// the heartbeat ended.
func (v *Scan) stopBeat() {
	if v.beatStop != nil {
		close(v.beatStop)
		v.beatStop = nil
	}
	v.beatEnded = true
}

// beat prints the progress of a stage beatEvery after the stage started,
// then beatEvery after the last line. A tick that fires just before Stop
// prints nothing.
func (v *Scan) beat() {
	v.mu.Lock()
	defer v.mu.Unlock()
	now := v.now()
	since := v.started
	if v.lastBeat.After(since) {
		since = v.lastBeat
	}
	if v.beatEnded || v.stage == "" || now.Sub(since) < beatEvery {
		return
	}
	s := v.snapshot()
	text := s.text(now, v.glyphs)
	if text == "" {
		return
	}
	v.lastBeat = now
	switch v.mode {
	case output.Agent:
		// The elapsed field tells a running stage from the line that ends it.
		line := fmt.Sprintf("progress: %s %d elapsed=%s", v.stage, v.done, humanize.Elapsed(now.Sub(v.started)))
		if s.waits() {
			line += " work=" + field(s.work.Name)
		}
		v.line(line)
	case output.Plain:
		v.line("[INFO] " + text)
	default:
		v.line(style.Faint(v.glyphs.Step+" ") + text)
	}
}
