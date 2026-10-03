package report

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/runner"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/printer"
	"github.com/safedep/vet/v2/plugin"
)

// CodeNoFinding is the error code of a finding id that no finding has. The
// command exits with code 2.
const CodeNoFinding = "usage_no_finding"

func newFinding(a *app.App) *cobra.Command {
	c := &cobra.Command{
		Use:   "finding",
		Short: "Read the findings of a saved scan",
		Long:  `Read one finding of a saved scan: its evidence, its place, its fix and its references.`,
	}
	c.AddCommand(newFindingShow(a))
	return c
}

func newFindingShow(a *app.App) *cobra.Command {
	var scan string
	var f state.Flags
	c := &cobra.Command{
		Use:   "show ID",
		Short: "Show one finding of a saved scan",
		Long: `Show one finding of the last scan of the current directory: what vet
found, where, why it matters, the evidence, the fix and the references.
The id is a finding id, or a unique prefix of it, as the scan view and
the reports print it. --scan names another scan. -o json prints the whole
finding.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			doc, err := runner.Load(cmd.Context(), a, scan, f)
			if err != nil {
				return err
			}
			var match []*finding.Finding
			for x, err := range doc.Findings(cmd.Context(), plugin.FindingQuery{IncludeSuppressed: true}) {
				if err != nil {
					return err
				}
				if strings.HasPrefix(x.ID, args[0]) {
					match = append(match, x)
				}
			}
			switch len(match) {
			case 0:
				return app.UsageErrorCode(CodeNoFinding, fmt.Sprintf("scan %s has no finding %q", doc.Header().Scan.ID, args[0]),
					"vet report show prints the id of each finding.")
			case 1:
			default:
				return app.UsageErrorCode(CodeNoFinding, fmt.Sprintf("%q matches %d findings", args[0], len(match)),
					"Type more characters of the id.")
			}
			p, err := a.Printer()
			if err != nil {
				return err
			}
			return p.Print(match[0], findingRows(match[0]))
		},
	}
	c.Flags().StringVar(&scan, "scan", "", "Scan id prefix, last, or report file. The default is the last scan")
	c.Flags().StringVar(&f.StateDir, "state-dir", "", "Directory of the scan index and the scan files")
	return c
}

func findingRows(f *finding.Finding) printer.Rows {
	rows := printer.Rows{Headers: []string{"FIELD", "VALUE"}}
	add := func(k, v string) {
		if v != "" {
			rows.Rows = append(rows.Rows, []string{k, escape.Line(v)})
		}
	}
	add("id", f.ID)
	add("control", f.ControlID)
	add("severity", string(f.Severity))
	add("confidence", string(f.Confidence))
	add("title", f.Title)
	add("subject", subject(f))
	if l := f.Locus; l != nil && l.Path != "" {
		where := l.Path
		if l.StartLine > 0 {
			where = fmt.Sprintf("%s:%d", l.Path, l.StartLine)
		}
		add("where", where)
		add("snippet", l.Snippet)
	}
	add("change", strings.ToLower(string(f.Change)))
	add("description", f.Description)
	for _, e := range f.Evidence {
		add("evidence", strings.TrimSpace(e.Source+": "+e.Summary+" "+e.URL))
	}
	if r := f.Remediation; r != nil {
		add("fix", r.Summary)
		add("fixed version", r.FixedVersion)
		add("command", r.Command)
	}
	for _, ref := range f.References {
		add("reference", ref)
	}
	if s := f.Suppression; s != nil {
		add("suppressed", s.Reason)
	}
	add("policy rule", f.PolicyRule)
	return rows
}
