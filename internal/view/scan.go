// Package view renders the stderr part of a scan: the step lines, the
// progress, the diagnostics and the gate line, for the rich, plain and
// agent modes. The report itself goes to stdout through a sink.
package view

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/progress"
	"github.com/safedep/vet/v2/internal/tui/section"
	"github.com/safedep/vet/v2/internal/tui/style"
	"github.com/safedep/vet/v2/report"
)

// Options configure a scan view.
type Options struct {
	Target  string
	BaseRef string
	// Animate shows a live progress bar in rich mode. The command sets it
	// when stderr is a terminal.
	Animate bool
	// Saved renders a saved report: there is no start line and no stage.
	Saved bool
}

// Scan is the stderr view of one scan. It implements engine.Observer.
type Scan struct {
	o    Options
	mode output.Mode

	mu      sync.Mutex
	stage   string
	index   int
	total   int
	done    int
	prog    *progress.Progress
	tracker *progress.Tracker
}

var stageText = map[string]string{
	engine.StageExtract:  "Read the manifests",
	engine.StageEnrich:   "Checked risk",
	engine.StageEvaluate: "Evaluated the controls",
	engine.StageReport:   "Wrote the report",
}

var stageUnit = map[string]string{
	engine.StageExtract:  "file",
	engine.StageEnrich:   "package",
	engine.StageEvaluate: "manifest",
}

// NewScan returns the view and prints the start line.
func NewScan(o Options) *Scan {
	v := &Scan{o: o, mode: output.CurrentMode()}
	mode := "full"
	if o.BaseRef != "" {
		mode = "delta"
	}
	switch {
	case o.Saved:
	case v.mode == output.Agent:
		v.line(fmt.Sprintf("INFO: scan started target=%s mode=%s", field(o.Target), mode))
	case o.BaseRef != "":
		v.line(style.Info(fmt.Sprintf("Comparing HEAD with %s", escape.Line(o.BaseRef))))
	}
	return v
}

// Stage ends the stage that runs and starts the next one.
func (v *Scan) Stage(name string, index, total int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.endStage()
	v.stage, v.index, v.total, v.done = name, index, total, 0
	if v.mode == output.Rich && v.o.Animate && name == engine.StageEnrich {
		v.prog = progress.New()
		v.tracker = v.prog.Track(stageText[name], 0)
	}
}

// Progress records the units done in the stage.
func (v *Scan) Progress(stage string, done, _ int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if stage != v.stage {
		return
	}
	if v.tracker != nil && done > v.done {
		v.tracker.Increment(int64(done - v.done))
	}
	v.done = done
}

// endStage prints the line of the stage that ends.
func (v *Scan) endStage() {
	if v.stage == "" {
		return
	}
	if v.tracker != nil {
		v.tracker.Done()
		v.prog.Wait()
		v.tracker, v.prog = nil, nil
	}
	text := stageText[v.stage]
	if unit := stageUnit[v.stage]; unit != "" && v.done > 0 {
		text = fmt.Sprintf("%s: %s", text, plural(v.done, unit))
	}
	switch v.mode {
	case output.Rich:
		v.line(fmt.Sprintf("%s [%d/%d] %s", style.Faint("›"), v.index, v.total, text))
	case output.Plain:
		v.line("[INFO] " + text)
	case output.Agent:
		v.line(fmt.Sprintf("progress: %s %d", v.stage, v.done))
	}
	v.stage = ""
}

// Finish ends the last stage, then prints the changes of a pull request
// scan, the diagnostics, the gate line and the next steps.
func (v *Scan) Finish(h *report.Header, t *report.Trailer, diags []*report.Diagnostic, changed Changes) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.endStage()
	if h.Scan.Mode == report.ScanModeDelta && v.mode != output.Agent {
		v.line(section.Hint(fmt.Sprintf("%s changed, %s changed. %s not shown.",
			plural(changed.Packages, "package"), plural(changed.Workflows, "workflow"), plural(changed.Unchanged, "unchanged package"))))
	}
	for _, d := range diags {
		v.diagnostic(d)
	}
	v.gate(h, t)
}

// Changes counts what a pull request changes.
type Changes struct {
	Packages, Workflows, Unchanged int
}

func (v *Scan) diagnostic(d *report.Diagnostic) {
	msg := escape.Line(d.Message)
	if d.Count > 1 {
		msg = fmt.Sprintf("%s (%d times)", msg, d.Count)
	}
	switch {
	case v.mode == output.Agent:
		level := "WARN"
		if d.Level == report.DiagnosticError {
			level = "ERR"
		}
		v.line(fmt.Sprintf("%s: diagnostic code=%s component=%s message=%s", level, d.Code, field(d.Component), field(msg)))
	case d.Level == report.DiagnosticError:
		v.fail(style.Error(fmt.Sprintf("%s: %s", d.Component, msg)))
	default:
		v.line(style.Warning(fmt.Sprintf("%s: %s", d.Component, msg)))
	}
}

func (v *Scan) gate(h *report.Header, t *report.Trailer) {
	g, sum := t.Gate, t.Summary
	if v.mode == output.Agent {
		switch g.Outcome {
		case report.GateFail:
			v.fail(fmt.Sprintf("ERR: gate failed%s findings=%d exit=1", gateFields(g), len(g.FindingIDs)))
		case report.GatePass:
			v.line(fmt.Sprintf("OK: gate passed%s findings=%d", gateFields(g), sum.Findings))
		default:
			v.line(fmt.Sprintf("INFO: scan done findings=%d gate=none", sum.Findings))
		}
		return
	}
	switch g.Outcome {
	case report.GateFail:
		v.fail(style.Error("Gate failed: " + gateReason(g)))
	case report.GatePass:
		v.line(style.Success("Gate passed: " + passReason(g)))
	default:
		if sum.Findings > 0 {
			v.line(section.Hint(fmt.Sprintf("%s. No gate set, so vet exits 0.", plural(sum.Findings, "finding"))))
		}
	}
	if v.mode == output.Rich && sum.Findings > 0 {
		id := ""
		if len(g.FindingIDs) > 0 {
			id = g.FindingIDs[0]
		}
		if id != "" {
			v.line(section.Hint("Details: vet report finding show " + id))
		}
		v.line(section.Hint("Report:  vet report show " + h.Scan.ID + " -o json"))
	}
}

func gateFields(g report.Gate) string {
	var b strings.Builder
	if g.FailOn != "" {
		fmt.Fprintf(&b, " fail_on=%s", g.FailOn)
	}
	if len(g.Rules) > 0 {
		fmt.Fprintf(&b, " rules=%s", strings.Join(g.Rules, ","))
	}
	return b.String()
}

func gateReason(g report.Gate) string {
	n := len(g.FindingIDs)
	var parts []string
	if g.FailOn != "" {
		parts = append(parts, fmt.Sprintf("%s at %s or above", plural(n, "finding"), g.FailOn))
	}
	if len(g.Rules) > 0 {
		parts = append(parts, "policy rule "+strings.Join(g.Rules, ", "))
	}
	if len(parts) == 0 {
		parts = append(parts, plural(n, "finding"))
	}
	return strings.Join(parts, ", ")
}

func passReason(g report.Gate) string {
	if g.FailOn != "" {
		return fmt.Sprintf("no finding at %s or above", g.FailOn)
	}
	return "no policy rule failed"
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// field quotes an agent field value that holds a space or a quote.
func field(s string) string {
	s = escape.Line(s)
	if s == "" || strings.ContainsAny(s, " \t\"=") {
		return fmt.Sprintf("%q", s)
	}
	return s
}

// line prints a line on stderr. -q keeps only the failure lines.
func (v *Scan) line(s string) { v.print(s, false) }

func (v *Scan) fail(s string) { v.print(s, true) }

func (v *Scan) print(s string, failure bool) {
	if output.CurrentVerbosity() <= output.Silent && !failure {
		return
	}
	writeLine(output.Stderr(), s)
}

// writeLine writes to stderr. A failed write to stderr has no place left
// to report it, so the view drops it.
func writeLine(w io.Writer, s string) {
	if _, err := fmt.Fprintln(w, s); err != nil {
		return
	}
}

var _ engine.Observer = (*Scan)(nil)
