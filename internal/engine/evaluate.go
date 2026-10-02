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
	return nil
}

func (r *run) evaluateManifest(ctx context.Context, m *model.Manifest) []finding.Finding {
	var out []finding.Finding
	seen := map[string]bool{}
	for _, c := range r.o.Controls {
		fs, err := c.Plugin.Evaluate(ctx, m, r.res.Scan)
		switch {
		case errors.Is(err, plugin.ErrUnavailable):
			r.diags.add(report.DiagnosticWarning, CodeControlUnavailable, c.ID,
				fmt.Sprintf("%s did not run on some manifests, because its data was not available", c.ID))
			continue
		case err != nil:
			r.diags.add(report.DiagnosticError, CodeControlFailed, c.ID, fmt.Sprintf("%s: %v", m.Path, err))
			continue
		}
		for _, f := range fs {
			if err := f.Validate(); err != nil {
				r.diags.add(report.DiagnosticError, CodeInvalidFinding, c.ID, err.Error())
				continue
			}
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
		if p.Usage.Imported {
			summary = fmt.Sprintf("The project imports the package in %s.", p.Usage.Files[0])
			if n := len(p.Usage.Files); n > 1 {
				summary = fmt.Sprintf("The project imports the package in %d files, for example %s.", n, p.Usage.Files[0])
			}
		}
		f.Evidence = append(f.Evidence, finding.Evidence{Source: "codeusage", Summary: summary})
		return
	}
}
