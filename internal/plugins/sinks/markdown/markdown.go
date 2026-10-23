// Package markdown is the markdown format, for a pull request comment or
// a job summary: the counts, the gate, a table with one row for each cause
// and the card of each cause.
package markdown

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/internal/render"
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

// maxTitle is the length of a title in the table, so that a long advisory
// summary keeps the comment readable.
const maxTitle = 100

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
	cols := []string{"Kind", "Control", "Subject", "Where"}
	if delta {
		cols = append(cols, "Change")
	}
	cols = append(cols, "Title")
	reach := h.Scan.Reach != nil && h.Scan.Reach.Status == report.ReachComputed
	if reach {
		cols = append(cols, "Reach")
	}
	gated := t.Gate.Outcome != report.GateNone
	if gated {
		cols = append(cols, "Gate")
	}
	cols = append(cols, "Finding")
	var open []*finding.Finding
	var suppressed []string
	err := render.EachFinding(ctx, r, func(f *finding.Finding) error {
		if f.Suppressed() {
			suppressed = append(suppressed, fmt.Sprintf("- `%s` %s: %s", cell(f.ControlID), code(render.Subject(f)), cell(render.Text(f.Suppression.Reason))))
			return nil
		}
		open = append(open, f)
		return nil
	})
	if err != nil {
		return err
	}
	groups := render.Groups(open)
	b.Reset()
	if len(groups) > 0 {
		writeHeader(&b, cols)
	}
	for _, g := range groups {
		f := g.Lead()
		cells := []string{g.Kind(), cell(f.ControlID), code(render.Subject(f)) + g.More(), code(render.Where(f))}
		if delta {
			cells = append(cells, strings.ToLower(string(f.Change)))
		}
		cells = append(cells, render.Bounded(render.Title(f), maxTitle))
		if reach {
			cells = append(cells, cell(g.Reach().Label()))
		}
		if gated {
			cells = append(cells, gateCell(f.Gate))
		}
		cells = append(cells, fmt.Sprintf("`%s`", f.ID))
		b.WriteString("| " + strings.Join(cells, " | ") + " |\n")
	}
	if len(groups) > 0 {
		b.WriteString("\n### Causes\n\n")
	}
	for _, g := range groups {
		card := render.NewCard(g)
		fmt.Fprintf(&b, "%s · %s\n\n", card.Head, render.ShortCode(render.Where(g.Lead())))
		for _, p := range card.Body {
			b.WriteString(p + "\n\n")
		}
		if len(card.Members) > 0 {
			fmt.Fprintf(&b, "<details><summary>%d more with this cause</summary>\n\n%s\n\n</details>\n\n", len(g.Findings)-1, strings.Join(card.Members, "\n"))
		}
		fmt.Fprintf(&b, "`%s`\n\n", g.Lead().ID)
	}
	if len(groups) == 0 {
		fmt.Fprintf(&b, "No findings. %d packages checked.\n", sum.Packages)
	}
	if len(suppressed) > 0 {
		if len(groups) == 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "<details><summary>%d suppressed</summary>\n\n%s\n\n</details>\n", len(suppressed), strings.Join(suppressed, "\n"))
	}
	_, err = io.WriteString(w, b.String())
	return err
}

func writeHeader(b *strings.Builder, cols []string) {
	sep := make([]string, len(cols))
	for i := range sep {
		sep[i] = "---"
	}
	b.WriteString("| " + strings.Join(cols, " | ") + " |\n| " + strings.Join(sep, " | ") + " |\n")
}

func gate(g report.Gate) string {
	if g.Outcome == report.GateFail {
		return "**FAIL**"
	}
	return string(g.Outcome)
}

// gateCell names what blocks or warns on a finding.
func gateCell(g *finding.GateRecord) string {
	if g == nil {
		return ""
	}
	return render.Markdown(render.Text(g.Label() + " " + g.Cause()))
}

// cell makes text safe in a table cell.
func cell(s string) string {
	return strings.NewReplacer("|", `\|`, "\n", " ", "<", "&lt;", ">", "&gt;").Replace(s)
}

// code puts text in a code span of a table cell.
func code(s string) string { return strings.ReplaceAll(render.Code(s), "|", `\|`) }
