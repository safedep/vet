package report

import (
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/app"
	"github.com/safedep/vet/v2/internal/reportdoc"
	"github.com/safedep/vet/v2/internal/runner"
	"github.com/safedep/vet/v2/internal/state"
	"github.com/safedep/vet/v2/internal/tui"
	"github.com/safedep/vet/v2/internal/tui/escape"
	"github.com/safedep/vet/v2/internal/tui/printer"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Diff is the result of "vet report diff".
type Diff struct {
	Base            string             `json:"base"`
	Head            string             `json:"head"`
	Added           []*finding.Finding `json:"added"`
	Removed         []*finding.Finding `json:"removed"`
	Unchanged       int                `json:"unchanged"`
	PackagesAdded   []string           `json:"packages_added"`
	PackagesRemoved []string           `json:"packages_removed"`
}

func newDiff(a *app.App) *cobra.Command {
	var f state.Flags
	c := &cobra.Command{
		Use:   "diff [BASE [HEAD]]",
		Short: "Compare the findings of two saved scans",
		Long: `Compare two saved reports. vet lists the findings that HEAD adds and the
findings that it removes, by finding id, and the packages that it adds and
removes. The default is the last two completed scans of the current
directory. With one argument, HEAD is the last scan. An argument is a scan
id prefix, "last" or a report file.`,
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			base, head, err := diffRefs(cmd, a, f, args)
			if err != nil {
				return err
			}
			b, err := runner.Load(ctx, a, base, f)
			if err != nil {
				return err
			}
			h, err := runner.Load(ctx, a, head, f)
			if err != nil {
				return err
			}
			warnModes(b.Header().Scan, h.Header().Scan)
			d, err := compare(cmd, b, h)
			if err != nil {
				return err
			}
			p, err := a.Printer()
			if err != nil {
				return err
			}
			return p.Print(d, diffRows(d))
		},
	}
	c.Flags().StringVar(&f.StateDir, "state-dir", "", "Directory of the scan index and the scan files")
	return c
}

// diffRefs picks the two reports. With no argument, they are the last two
// completed scans of the current target.
func diffRefs(cmd *cobra.Command, a *app.App, f state.Flags, args []string) (string, string, error) {
	switch len(args) {
	case 2:
		return args[0], args[1], nil
	case 1:
		return args[0], runner.Last, nil
	}
	_, s, err := runner.Store(cmd.Context(), a, f)
	if err != nil {
		return "", "", err
	}
	defer closeStore(s)
	es, err := runner.TargetScans(cmd.Context(), s, state.StatusCompleted)
	if err != nil {
		return "", "", err
	}
	if len(es) < 2 {
		return "", "", app.UsageErrorCode(runner.CodeNoScan, "vet report diff needs two completed scans of this directory",
			"Run vet scan again, or name two scans: vet report diff BASE HEAD.")
	}
	return es[1].ID, es[0].ID, nil
}

// warnModes warns when one scan is a pull request scan and the other is a
// full scan. A pull request scan holds only the findings of the changes, so
// the diff lists the other findings as added or removed.
func warnModes(base, head report.ScanInfo) {
	if base.Mode == head.Mode {
		return
	}
	tui.Warning("Scan %s is a %s and scan %s is a %s. A pull request scan holds only the findings of the changes, so this diff is not complete.",
		shortID(base.ID), modeName(base.Mode), shortID(head.ID), modeName(head.Mode))
}

func modeName(m report.ScanMode) string {
	if m == report.ScanModeDelta {
		return "pull request scan"
	}
	return "full scan"
}

func compare(cmd *cobra.Command, base, head *reportdoc.Doc) (*Diff, error) {
	ctx := cmd.Context()
	d := &Diff{
		Base: base.Header().Scan.ID, Head: head.Header().Scan.ID, Added: []*finding.Finding{}, Removed: []*finding.Finding{},
		PackagesAdded: []string{}, PackagesRemoved: []string{},
	}
	ids := func(doc *reportdoc.Doc) (map[string]*finding.Finding, error) {
		out := map[string]*finding.Finding{}
		for f, err := range doc.Findings(ctx, plugin.FindingQuery{}) {
			if err != nil {
				return nil, err
			}
			out[f.ID] = f
		}
		return out, nil
	}
	purls := func(doc *reportdoc.Doc) (map[string]bool, error) {
		out := map[string]bool{}
		for p, err := range doc.Packages(ctx, plugin.PackageQuery{}) {
			if err != nil {
				return nil, err
			}
			out[p.ID.PURL()] = true
		}
		return out, nil
	}
	bf, err := ids(base)
	if err != nil {
		return nil, err
	}
	hf, err := ids(head)
	if err != nil {
		return nil, err
	}
	for id, f := range hf {
		if _, ok := bf[id]; ok {
			d.Unchanged++
		} else {
			d.Added = append(d.Added, f)
		}
	}
	for id, f := range bf {
		if _, ok := hf[id]; !ok {
			d.Removed = append(d.Removed, f)
		}
	}
	slices.SortFunc(d.Added, finding.Compare)
	slices.SortFunc(d.Removed, finding.Compare)

	bp, err := purls(base)
	if err != nil {
		return nil, err
	}
	hp, err := purls(head)
	if err != nil {
		return nil, err
	}
	for p := range hp {
		if !bp[p] {
			d.PackagesAdded = append(d.PackagesAdded, p)
		}
	}
	for p := range bp {
		if !hp[p] {
			d.PackagesRemoved = append(d.PackagesRemoved, p)
		}
	}
	slices.Sort(d.PackagesAdded)
	slices.Sort(d.PackagesRemoved)
	return d, nil
}

func diffRows(d *Diff) printer.Rows {
	rows := printer.Rows{
		Headers: []string{"CHANGE", "SEVERITY", "CONTROL", "SUBJECT", "FINDING"},
		Empty:   "No finding was added or removed.",
		Footer:  strings.Join([]string{"base " + shortID(d.Base), "head " + shortID(d.Head)}, ", "),
	}
	add := func(change string, fs []*finding.Finding) {
		for _, f := range fs {
			rows.Rows = append(rows.Rows, []string{change, string(f.Severity), escape.Line(f.ControlID), subject(f), f.ID})
		}
	}
	add("added", d.Added)
	add("removed", d.Removed)
	return rows
}

func subject(f *finding.Finding) string {
	s := f.Subject
	switch {
	case s.Package != nil:
		return escape.Line(s.Package.PURL)
	case s.File != nil:
		return escape.Line(s.File.Path)
	case s.Manifest != nil:
		return escape.Line(s.Manifest.Path)
	case s.Application != nil:
		return escape.Line(s.Application.Root)
	}
	return ""
}
