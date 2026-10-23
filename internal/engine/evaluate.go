package engine

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/safedep/dry/log"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/technique"
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
		var fs []finding.Finding
		// A removed manifest has no file at the head, and introduced drops
		// each of its findings.
		if m.Change != model.ChangeRemoved {
			m.Root = r.rootOf(m)
			fs = r.evaluateManifest(ctx, m)
		}
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
			r.setReach(&f, m)
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
func (r *run) valid(pluginID, where string, fs []finding.Finding, err error) []finding.Finding {
	switch {
	case errors.Is(err, plugin.ErrUnavailable):
		r.diags.add(report.DiagnosticWarning, report.CodeControlUnavailable, pluginID,
			fmt.Sprintf("%s did not run on some manifests, because its data was not available", pluginID))
		return nil
	case err != nil:
		r.diags.add(report.DiagnosticError, report.CodeControlFailed, pluginID, fmt.Sprintf("%s: %v", where, err))
		return nil
	}
	out := fs[:0:0]
	for _, f := range fs {
		if err := f.Validate(); err != nil {
			r.diags.add(report.DiagnosticError, report.CodeInvalidFinding, pluginID, err.Error())
			continue
		}
		f.Attack = r.attack(pluginID, f.ControlID)
		out = append(out, f)
	}
	return out
}

// attack returns a copy of the attack of a control, or nil. The plugin must
// describe the control, so that a plugin cannot mark its finding as an
// attack with the id of an attack control of another plugin.
func (r *run) attack(pluginID, controlID string) *finding.Attack {
	a, ok := r.attacks[pluginID][controlID]
	if !ok {
		return nil
	}
	return &finding.Attack{Technique: a.Technique, MITRE: slices.Clone(a.MITRE)}
}

// attacksOf reads the attack controls from the info of each control
// plugin. A technique that the registry does not have, as from a plugin
// outside vet, gives an attack with no ATT&CK ids. TestTechniqueRegistry
// makes sure that each built-in attack control names a known technique.
func attacksOf(cs []Control) map[string]map[string]finding.Attack {
	out := map[string]map[string]finding.Attack{}
	for _, c := range cs {
		d, ok := c.Plugin.(plugin.Describer)
		if !ok {
			continue
		}
		for _, info := range d.Controls() {
			if !info.Attack {
				continue
			}
			if out[c.ID] == nil {
				out[c.ID] = map[string]finding.Attack{}
			}
			a, ok := technique.Attack(info.Technique)
			if !ok {
				log.Warnf("engine: control %s of plugin %s names the technique %q, which vet does not know", info.ID, c.ID, info.Technique)
			}
			out[c.ID][info.ID] = a
		}
	}
	return out
}

// annotateUsage adds the code usage of the package of a finding as
// evidence (control catalog, phase 3: reachability annotation). It changes
// no severity.
func annotateUsage(f *finding.Finding, m *model.Manifest) {
	p := packageOf(f, m)
	if p == nil || p.Usage == nil {
		return
	}
	summary := "No source file of the project imports the package."
	switch n := len(p.Usage.Files); {
	case !p.Usage.Imported && p.Usage.Incomplete:
		summary = "vet stopped the code analysis before it read every source file, so it cannot tell whether the project imports the package."
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
}
