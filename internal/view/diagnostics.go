package view

import (
	"cmp"
	"fmt"
	"slices"
	"strings"

	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/internal/tui/section"
	"github.com/safedep/vet/v2/internal/tui/style"
	"github.com/safedep/vet/v2/report"
)

// shownDiagnostics is the number of diagnostic lines that a human sees. A
// scan of a large repository can have hundreds, as for a test corpus of
// malformed files. -v and the agent mode show all of them.
const shownDiagnostics = 5

// diagGroup holds the diagnostics of one level, component and code. A
// person reads one line for the group.
type diagGroup struct {
	first   *report.Diagnostic
	records int
	times   int
}

func (v *Scan) diagnostics(h *report.Header, diags []*report.Diagnostic) {
	if v.mode == output.Agent || output.CurrentVerbosity() == output.Verbose {
		for _, d := range diags {
			v.diagnostic(d, diagText(d))
		}
		return
	}
	groups := groupDiagnostics(diags)
	hidden, grouped := 0, false
	for i, g := range groups {
		if i >= shownDiagnostics {
			hidden += g.records
			continue
		}
		grouped = grouped || g.records > 1
		v.diagnostic(g.first, g.text())
	}
	if hidden == 0 && !grouped {
		return
	}
	var hint string
	if hidden > 0 {
		hint = plural(hidden, "more diagnostic") + ". "
	}
	if h.Scan.ID != "" {
		hint += "Show all: vet report show " + h.Scan.ID + " -v"
	} else {
		hint += "Run with -v to show all."
	}
	v.line(section.Hint(hint))
}

// groupDiagnostics groups the diagnostics by level, component and code.
// The groups of errors come first, then the groups in report order.
func groupDiagnostics(diags []*report.Diagnostic) []*diagGroup {
	var groups []*diagGroup
	byKey := map[[3]string]*diagGroup{}
	for _, d := range diags {
		key := [3]string{string(d.Level), d.Component, d.Code}
		g, ok := byKey[key]
		if !ok {
			g = &diagGroup{first: d}
			byKey[key] = g
			groups = append(groups, g)
		}
		g.records++
		g.times += max(d.Count, 1)
	}
	slices.SortStableFunc(groups, func(a, b *diagGroup) int {
		return cmp.Compare(levelRank(a.first.Level), levelRank(b.first.Level))
	})
	return groups
}

func (g *diagGroup) text() string {
	if g.records == 1 {
		return diagText(g.first)
	}
	return fmt.Sprintf("%s (and %d more like it)", cleanMessage(g.first.Message), g.times-1)
}

func levelRank(l report.DiagnosticLevel) int {
	if l == report.DiagnosticError {
		return 0
	}
	return 1
}

func diagText(d *report.Diagnostic) string {
	msg := cleanMessage(d.Message)
	if d.Count > 1 {
		msg = fmt.Sprintf("%s (%d times)", msg, d.Count)
	}
	return msg
}

// cleanMessage puts a message on one line. Some parsers put line breaks,
// or an escaped "\n", in their errors.
func cleanMessage(msg string) string {
	msg = strings.ReplaceAll(msg, `\n`, " ")
	return escape.Line(strings.Join(strings.Fields(msg), " "))
}

func (v *Scan) diagnostic(d *report.Diagnostic, msg string) {
	switch {
	case v.mode == output.Agent:
		level := "WARN"
		if d.Level == report.DiagnosticError {
			level = "ERR"
		}
		v.line(fmt.Sprintf("%s: diagnostic code=%s component=%s message=%s", level, d.Code, field(d.Component), field(msg)))
	case d.Level == report.DiagnosticError:
		v.fail(style.Error(fmt.Sprintf("%s: %s", escape.Line(d.Component), msg)))
	default:
		v.line(style.Warning(fmt.Sprintf("%s: %s", escape.Line(d.Component), msg)))
	}
}
