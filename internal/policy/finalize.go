package policy

import (
	"cmp"
	"context"
	"fmt"
	"iter"
	"maps"
	"slices"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Diagnostic codes of the policy.
const (
	CodeSuppressionExpired = "policy_suppression_expired"
	CodeRuleFailed         = "policy_rule_failed"
	CodeSourceUnavailable  = "policy_source_unavailable"
)

// RuleControl is the control id of the findings that the package rules
// make.
const RuleControl = "policy"

// Store is the scan that Finalize reads and updates.
type Store interface {
	Findings(ctx context.Context, q plugin.FindingQuery) iter.Seq2[*finding.Finding, error]
	FindingManifest(ctx context.Context, findingID string) (string, error)
	Manifests(ctx context.Context) iter.Seq2[*model.Manifest, error]
	Manifest(ctx context.Context, id string) (*model.Manifest, error)
	// ReplaceFinding writes a finding, or adds it when the scan does not
	// have it.
	ReplaceFinding(ctx context.Context, manifestID string, f *finding.Finding) error
	DeleteFindings(ctx context.Context, controlID string) error
	AddDiagnostic(ctx context.Context, d *report.Diagnostic) error
}

// Finalize applies the policy to every finding of a scan, writes the
// findings whose suppression or rule changed, records the policy
// diagnostics, and returns the gate.
func (e *Evaluator) Finalize(ctx context.Context, s Store) (report.Gate, error) {
	// The findings of an earlier evaluation, as of "vet report show
	// --policy", do not reach the rules.
	if err := s.DeleteFindings(ctx, RuleControl); err != nil {
		return report.Gate{}, err
	}
	var all []*finding.Finding
	for f, err := range s.Findings(ctx, plugin.FindingQuery{IncludeSuppressed: true}) {
		if err != nil {
			return report.Gate{}, err
		}
		all = append(all, f)
	}
	slices.SortFunc(all, finding.Compare)

	gate := e.NewGate()
	manifests := map[string]*model.Manifest{}
	diags := map[string]*report.Diagnostic{}
	for _, f := range all {
		mid, err := s.FindingManifest(ctx, f.ID)
		if err != nil {
			return report.Gate{}, err
		}
		m, err := manifestOf(ctx, s, manifests, mid)
		if err != nil {
			return report.Gate{}, err
		}
		before := *f
		o := e.Apply(f, packageOf(m, f), m)
		gate.Add(f, o)
		if changed(&before, f) {
			if err := s.ReplaceFinding(ctx, mid, f); err != nil {
				return report.Gate{}, err
			}
		}
		for _, ref := range o.Expired {
			addDiag(diags, CodeSuppressionExpired, fmt.Sprintf("%s expired. It no longer suppresses findings.", ref))
		}
		for _, err := range o.Errors {
			addDiag(diags, CodeRuleFailed, err.Error())
		}
	}
	if err := e.packageRules(ctx, s, gate, diags); err != nil {
		return report.Gate{}, err
	}
	for _, msg := range e.unavailable {
		addDiag(diags, CodeSourceUnavailable, msg)
	}
	for _, k := range slices.Sorted(maps.Keys(diags)) {
		if err := s.AddDiagnostic(ctx, diags[k]); err != nil {
			return report.Gate{}, err
		}
	}
	return gate.Result(), nil
}

// packageRules runs each package rule on each package. In pull request
// mode, it skips the packages that the change keeps or removes. A match
// adds a finding that names the rule. The other rules do not evaluate it,
// and --fail-on does not apply to it: the action of the rule decides.
func (e *Evaluator) packageRules(ctx context.Context, s Store, gate *Gate, diags map[string]*report.Diagnostic) error {
	var rules []*Rule
	for i := range e.p.Rules {
		if r := &e.p.Rules[i]; r.Scope() == ScopePackage {
			rules = append(rules, r)
		}
	}
	if len(rules) == 0 {
		return nil
	}
	for m, err := range s.Manifests(ctx) {
		if err != nil {
			return err
		}
		for _, p := range m.Packages {
			if p.Change != model.ChangeNone && !p.Change.Introduces() {
				continue
			}
			vars, err := packageRuleInput(p, m, e.now).activation()
			if err != nil {
				return err
			}
			for _, r := range rules {
				ok, err := r.expr.matchVars(vars)
				if err != nil {
					addDiag(diags, CodeRuleFailed, fmt.Sprintf("rule %s: %v", r.ID, err))
				}
				// A fail rule that cannot run must not let a package pass.
				if !ok && (err == nil || r.Action != ActionFail) {
					continue
				}
				f := e.ruleFinding(r, m, p, err != nil)
				o := e.applyRule(f, r, err != nil)
				gate.Add(f, o)
				for _, ref := range o.Expired {
					addDiag(diags, CodeSuppressionExpired, fmt.Sprintf("%s expired. It no longer suppresses findings.", ref))
				}
				if err := s.ReplaceFinding(ctx, m.ID, f); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ruleFinding is the finding of a package rule on a package. broken is
// true when the rule did not evaluate on the package.
func (e *Evaluator) ruleFinding(r *Rule, m *model.Manifest, p *model.Package, broken bool) *finding.Finding {
	title := r.Description
	switch {
	case broken:
		title = "Policy rule " + r.ID + " did not evaluate on the package"
	case title == "":
		title = "The package matches policy rule " + r.ID
	}
	desc := fmt.Sprintf("The policy rule %s matches the package.", r.ID)
	if broken {
		desc = fmt.Sprintf("The policy rule %s did not evaluate on the package. A fail rule that cannot run fails the gate.", r.ID)
	}
	f := finding.ForPackage(finding.Meta{
		ControlID: RuleControl, Family: finding.FamilyPolicy, Severity: cmp.Or(r.Severity, finding.SeverityInfo),
		Title: title, Description: desc,
	}, m.Path, p, finding.Key{Discriminator: r.ID})
	return &f
}

func manifestOf(ctx context.Context, s Store, cache map[string]*model.Manifest, id string) (*model.Manifest, error) {
	if id == "" {
		return nil, nil
	}
	if m, ok := cache[id]; ok {
		return m, nil
	}
	m, err := s.Manifest(ctx, id)
	if err != nil {
		return nil, err
	}
	cache[id] = m
	return m, nil
}

func packageOf(m *model.Manifest, f *finding.Finding) *model.Package {
	if m == nil || f.Subject.Package == nil {
		return nil
	}
	id, err := f.Subject.Package.PackageVersion()
	if err != nil {
		return nil
	}
	return m.Package(id)
}

func changed(a, b *finding.Finding) bool {
	if !a.Gate.Equal(b.Gate) || a.Suppressed() != b.Suppressed() {
		return true
	}
	return a.Suppressed() && (a.Suppression.Rule != b.Suppression.Rule || a.Suppression.Reason != b.Suppression.Reason)
}

func addDiag(diags map[string]*report.Diagnostic, code, msg string) {
	key := code + "\x00" + msg
	if d, ok := diags[key]; ok {
		d.Count++
		return
	}
	diags[key] = &report.Diagnostic{Level: report.DiagnosticWarning, Code: code, Component: "policy", Message: strings.TrimSpace(msg), Count: 1}
}
