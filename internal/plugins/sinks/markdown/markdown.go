// Package markdown is the markdown format, for a pull request comment or
// a job summary: the counts, the gate and a table of the findings.
package markdown

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/sinks/internal/render"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the format name.
const Name = "markdown"

// Sink writes the markdown format.
type Sink struct{}

// New builds the sink. It has no options.
func New(cfg plugin.Config) (plugin.Sink, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, err
	}
	return Sink{}, nil
}

// Write writes the summary and the findings.
func (Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	h, t := r.Header(), r.Trailer()
	var b strings.Builder
	fmt.Fprintf(&b, "## vet %s\n\n", h.Scan.Kind)
	sum := t.Summary
	fmt.Fprintf(&b, "| Packages | Findings | Critical | High | Suppressed | Gate |\n| ---: | ---: | ---: | ---: | ---: | --- |\n")
	fmt.Fprintf(&b, "| %d | %d | %d | %d | %d | %s |\n\n", sum.Packages, sum.Findings,
		sum.BySeverity[finding.SeverityCritical], sum.BySeverity[finding.SeverityHigh], sum.Suppressed, gate(t.Gate))
	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}

	delta := h.Scan.Mode == report.ScanModeDelta
	cols := []string{"Severity", "Control", "Subject", "Where"}
	if delta {
		cols = append(cols, "Change")
	}
	cols = append(cols, "Finding")
	var suppressed []string
	wrote := false
	err := render.EachFinding(ctx, r, func(f *finding.Finding) error {
		if f.Suppressed() {
			suppressed = append(suppressed, fmt.Sprintf("- `%s` %s: %s", cell(f.ControlID), code(render.Subject(f)), cell(render.Text(f.Suppression.Reason))))
			return nil
		}
		if !wrote {
			if err := tableHeader(w, cols); err != nil {
				return err
			}
			wrote = true
		}
		cells := []string{string(f.Severity), cell(f.ControlID), code(render.Subject(f)), code(render.Where(f))}
		if delta {
			cells = append(cells, strings.ToLower(string(f.Change)))
		}
		cells = append(cells, fmt.Sprintf("`%s`", f.ID))
		_, err := io.WriteString(w, "| "+strings.Join(cells, " | ")+" |\n")
		return err
	})
	if err != nil {
		return err
	}
	var tail strings.Builder
	if !wrote {
		fmt.Fprintf(&tail, "No findings. %d packages checked.\n", sum.Packages)
	}
	if len(suppressed) > 0 {
		fmt.Fprintf(&tail, "\n<details><summary>%d suppressed</summary>\n\n%s\n\n</details>\n", len(suppressed), strings.Join(suppressed, "\n"))
	}
	_, err = io.WriteString(w, tail.String())
	return err
}

func tableHeader(w io.Writer, cols []string) error {
	sep := make([]string, len(cols))
	for i := range sep {
		sep[i] = "---"
	}
	_, err := io.WriteString(w, "| "+strings.Join(cols, " | ")+" |\n| "+strings.Join(sep, " | ")+" |\n")
	return err
}

func gate(g report.Gate) string {
	if g.Outcome == report.GateFail {
		return "**FAIL**"
	}
	return string(g.Outcome)
}

// cell makes text safe in a table cell.
func cell(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ", "<", "&lt;", ">", "&gt;").Replace(s)
}

// code puts text in a code span that its backticks cannot close.
func code(s string) string {
	return "`" + strings.NewReplacer("|", `\|`, "\n", " ", "`", "'").Replace(s) + "`"
}
