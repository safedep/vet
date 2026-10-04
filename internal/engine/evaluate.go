package engine

import (
	"context"
	"errors"
	"fmt"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// evaluate runs every control on every manifest. It starts from no
// findings, because evaluation is local and fast, and the controls or the
// policy can change between two runs of one scan.
func (r *run) evaluate(ctx context.Context) error {
	scan := r.res.Scan
	if err := scan.ClearFindings(ctx); err != nil {
		return err
	}
	ids, err := scan.UnevaluatedManifests(ctx)
	if err != nil {
		return err
	}
	for i, id := range ids {
		if err := ctx.Err(); err != nil {
			return err
		}
		m, err := scan.Manifest(ctx, id)
		if err != nil {
			return err
		}
		m.Root = r.rootOf(m)
		fs := r.evaluateManifest(ctx, m)
		if err := scan.AddFindings(ctx, m.ID, fs); err != nil {
			return err
		}
		r.o.Observer.Progress(StageEvaluate, i+1, len(ids))
	}
	return scan.AddFindings(ctx, "", r.evaluateApplication(ctx))
}

func (r *run) evaluateManifest(ctx context.Context, m *model.Manifest) []finding.Finding {
	var out []finding.Finding
	seen := map[string]bool{}
	for _, c := range r.o.Controls {
		fs, err := c.Plugin.Evaluate(ctx, m, r.res.Scan)
		for _, f := range r.valid(c.ID, m.Path, fs, err) {
			if seen[f.ID] || (r.o.BaseRef != "" && !introduced(f, m)) {
				continue
			}
			seen[f.ID] = true
			annotateUsage(&f, m)
			out = append(out, f)
		}
	}
	return out
}

// evaluateApplication runs each application control once.
func (r *run) evaluateApplication(ctx context.Context) []finding.Finding {
	var out []finding.Finding
	seen := map[string]bool{}
	for _, c := range r.o.Controls {
		ac, ok := c.Plugin.(plugin.ApplicationControl)
		if !ok {
			continue
		}
		fs, err := ac.EvaluateApplication(ctx, r.res.Scan)
		for _, f := range r.valid(c.ID, "application", fs, err) {
			if !seen[f.ID] {
				seen[f.ID] = true
				out = append(out, f)
			}
		}
	}
	return out
}

// valid returns the findings of a control that pass validation. An error of
// the control, or an invalid finding, becomes a diagnostic.
func (r *run) valid(controlID, where string, fs []finding.Finding, err error) []finding.Finding {
	switch {
	case errors.Is(err, plugin.ErrUnavailable):
		r.diags.add(report.DiagnosticWarning, CodeControlUnavailable, controlID,
			fmt.Sprintf("%s did not run on some manifests, because its data was not available", controlID))
		return nil
	case err != nil:
		r.diags.add(report.DiagnosticError, CodeControlFailed, controlID, fmt.Sprintf("%s: %v", where, err))
		return nil
	}
	out := fs[:0:0]
	for _, f := range fs {
		if err := f.Validate(); err != nil {
			r.diags.add(report.DiagnosticError, CodeInvalidFinding, controlID, err.Error())
			continue
		}
		out = append(out, f)
	}
	return out
}

// annotateUsage adds the code usage of the package of a finding as
// evidence (control catalog, phase 3: reachability annotation). It changes
// no severity.
func annotateUsage(f *finding.Finding, m *model.Manifest) {
	if f.Subject.Kind != finding.SubjectPackage || f.Subject.Package == nil {
		return
	}
	for _, p := range m.Packages {
		if p.ID.PURL() != f.Subject.Package.PURL || p.Usage == nil {
			continue
		}
		summary := "No source file of the project imports the package."
		switch n := len(p.Usage.Files); {
		case !p.Usage.Imported:
		case n == 0:
			summary = "The project imports the package."
		case n == 1:
			summary = fmt.Sprintf("%s imports the package.", p.Usage.Files[0])
		default:
			others := "1 other file"
			if n > 2 {
				others = fmt.Sprintf("%d other files", n-1)
			}
			summary = fmt.Sprintf("%s and %s import the package.", p.Usage.Files[0], others)
		}
		f.Evidence = append(f.Evidence, finding.Evidence{Source: "codeusage", Summary: summary})
		return
	}
}
