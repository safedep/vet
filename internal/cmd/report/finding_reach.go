package report

import (
	"fmt"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// reachRows adds the reach of a finding: its label and hint, the call
// path, the entry points of a search that found no path, and the symbol
// record.
func reachRows(r *finding.Reach, scan *report.ReachInfo, add func(k, v string)) {
	if r == nil {
		return
	}
	add("reach", r.Label())
	add("reach help", r.Cause.Help())
	for i, h := range r.Path {
		add("path", hopText(i, h))
	}
	if r.Level == finding.ReachNotCalled && scan != nil && scan.Roots != nil {
		add("searched from", fmt.Sprintf("%d entry points. vet report root list lists them.", scan.Roots.Total))
	}
	if len(r.Via) > 0 {
		add("via", strings.Join(r.Via, " → "))
	}
	for _, s := range r.Imports {
		add("import", fmt.Sprintf("%s:%d", s.File, s.Line))
	}
	for _, s := range r.FixSites {
		add("fix site", s)
	}
	if s := r.Symbols; s != nil {
		add("symbol record", strings.Join(nonEmpty(s.Record, s.Coverage, s.Review, s.Source, s.License), ", "))
	}
}

// hopText writes one hop of a call path. The first hop is the entry point
// and names the rule that found it. Each other hop names the line that
// calls it, and the kind and the confidence of the call.
func hopText(i int, h model.PathHop) string {
	if i == 0 {
		root := h.Root
		if root == report.RootQuery {
			root = "--entrypoint"
		}
		return fmt.Sprintf("%s (root: %s)", h.Function, root)
	}
	text := "→ " + h.Function
	if h.File != "" {
		text += fmt.Sprintf(" at %s:%d", h.File, h.Line)
	}
	if parts := nonEmpty(h.Edge, h.Confidence); len(parts) > 0 {
		text += " (" + strings.Join(parts, ", ") + ")"
	}
	return text
}

func nonEmpty(values ...string) []string {
	var out []string
	for _, v := range values {
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}
