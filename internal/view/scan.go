// Package view renders the stderr part of a scan: the step lines, the
// progress, the diagnostics, the gate line and the next steps, for the
// rich, plain and agent modes. The report itself goes to stdout through a
// sink.
package view

import (
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/overview"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/humanize"
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
	// Kind is the kind of the scan. An endpoint audit names its steps for
	// the machine.
	Kind report.ScanKind
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
	now  func() time.Time

	mu      sync.Mutex
	stage   string
	index   int
	steps   int
	done    int
	total   int
	started time.Time
	bar     *progress.Bar
	files   []string
}

// shownElapsed is the shortest stage that a step line gives the run time of.
const shownElapsed = time.Second

// NewScan returns the view and prints the start line.
func NewScan(o Options) *Scan {
	v := &Scan{o: o, mode: output.CurrentMode(), now: time.Now}
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
func (v *Scan) Stage(name string, index, steps int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.endStage()
	v.stage, v.index, v.steps, v.done, v.total, v.started = name, index, steps, 0, 0, v.now()
}

// Progress records the units done in the stage. The enrich stage shows a
// live bar once it knows the number of packages.
func (v *Scan) Progress(stage string, done, total int) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if stage != v.stage {
		return
	}
	v.done, v.total = done, total
	if stage != engine.StageEnrich || total == 0 || !v.live() {
		return
	}
	if v.bar == nil {
		v.bar = progress.Start("Checking "+plural(total, "package"), total)
	}
	v.bar.Set(done)
}

// live reports whether the view draws a live bar: on a terminal, in rich
// mode, and not with -q.
func (v *Scan) live() bool {
	return v.mode == output.Rich && v.o.Animate && output.CurrentVerbosity() > output.Silent
}

// Stop removes the live bar of a scan that ends before Finish, for
// example on a signal.
func (v *Scan) Stop() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.stopBar()
}

func (v *Scan) stopBar() {
	if v.bar != nil {
		v.bar.Stop()
		v.bar = nil
	}
}

// Report ends the report stage before the report goes out, so that its
// step line comes before a report on the terminal. files are the report
// files that the scan writes.
func (v *Scan) Report(files []string) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.files = files
	v.endStage()
}

// endStage prints the line of the stage that ends.
func (v *Scan) endStage() {
	if v.stage == "" {
		return
	}
	v.stopBar()
	text := stepText(v.o.Kind, v.stage, max(v.done, v.total), v.files)
	if d := v.now().Sub(v.started); d >= shownElapsed && v.stage != engine.StageReport {
		text += " in " + humanize.Elapsed(d)
	}
	switch v.mode {
	case output.Rich:
		v.line(fmt.Sprintf("%s [%d/%d] %s", style.Faint("›"), v.index, v.steps, text))
	case output.Plain:
		v.line("[INFO] " + text)
	case output.Agent:
		v.line(fmt.Sprintf("progress: %s %d", v.stage, v.done))
	}
	v.stage = ""
}

func stepText(kind report.ScanKind, stage string, n int, files []string) string {
	switch stage {
	case engine.StageExtract:
		if kind == report.ScanKindEndpoint {
			return "Read the tools on this machine"
		}
		return counted("Read the manifests", n, "file")
	case engine.StageEnrich:
		return "Checked " + plural(n, "package")
	case engine.StageEvaluate:
		return counted("Evaluated the controls", n, "manifest")
	}
	if len(files) == 0 {
		return "Report"
	}
	return "Report: " + escape.Line(joinAnd(files))
}

func counted(text string, n int, unit string) string {
	if n == 0 {
		return text
	}
	return fmt.Sprintf("%s: %s", text, plural(n, unit))
}

// Finish ends the last stage, then prints the changes of a pull request
// scan, a missing manifest, the diagnostics, the gate line and the next
// steps.
func (v *Scan) Finish(h *report.Header, t *report.Trailer, s overview.Overview) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.endStage()
	if h.Scan.Mode == report.ScanModeDelta && v.mode != output.Agent {
		v.line(section.Hint(fmt.Sprintf("%s changed, %s changed. %s not shown.",
			plural(s.Changes.Packages, "package"), plural(s.Changes.Workflows, "workflow"), plural(s.Changes.Unchanged, "unchanged package"))))
	}
	v.noManifest(h, t)
	v.diagnostics(h, s.Diagnostics)
	v.gate(t)
	v.next(h, t, s)
}

// noManifest warns about a scan that read no manifest. Such a scan has no
// finding, and a person can take it for a clean result.
func (v *Scan) noManifest(h *report.Header, t *report.Trailer) {
	if t.Summary.Manifests > 0 || h.Scan.Kind == report.ScanKindEndpoint {
		return
	}
	if v.mode == output.Agent {
		v.line("WARN: no manifest found target=" + field(h.Scan.Target))
		return
	}
	v.line(style.Warning("vet found no manifest in " + escape.Line(targetName(h.Scan))))
	v.line(section.Hint("vet reads lockfiles (package-lock.json, go.mod and more), SBOMs and workflows."))
}

// targetName names the target for a person: the absolute path of a
// directory or a file, else the target as the user gave it.
func targetName(s report.ScanInfo) string {
	if filepath.IsAbs(s.TargetKey) {
		return s.TargetKey
	}
	return s.Target
}

func (v *Scan) gate(t *report.Trailer) {
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

// gateReason counts the findings that failed the gate and names the gate.
func gateReason(g report.Gate) string {
	n := plural(len(g.FindingIDs), "finding")
	if g.FailOn != "" && len(g.Rules) == 0 {
		return fmt.Sprintf("%s %s (--fail-on %s)", n, failOnText(g.FailOn), g.FailOn)
	}
	var gates []string
	if g.FailOn != "" {
		gates = append(gates, "--fail-on "+string(g.FailOn))
	}
	if len(g.Rules) > 0 {
		gates = append(gates, rulesText(g.Rules))
	}
	if len(gates) == 0 {
		return n
	}
	return fmt.Sprintf("%s (%s)", n, strings.Join(gates, ", "))
}

func rulesText(rules []string) string {
	if len(rules) == 1 {
		return "policy rule " + rules[0]
	}
	return "policy rules " + joinAnd(rules)
}

func passReason(g report.Gate) string {
	if g.FailOn != "" {
		return fmt.Sprintf("no finding %s (--fail-on %s)", failOnText(g.FailOn), g.FailOn)
	}
	return "no policy rule failed"
}

// failOnText names the findings that a --fail-on value fails on.
func failOnText(t report.FailOn) string {
	if t == report.FailOnAttacks {
		return "of an attack control"
	}
	return fmt.Sprintf("at %s or above", t)
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}

// joinAnd joins words as a list in a sentence: "a", "a and b", "a, b and c".
func joinAnd(words []string) string {
	if len(words) < 2 {
		return strings.Join(words, "")
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
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
