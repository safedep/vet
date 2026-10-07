package policy

import (
	"context"
	"fmt"
	"iter"
	"maps"
	"reflect"
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

// Store is the scan that Finalize reads and updates.
type Store interface {
	Findings(ctx context.Context, q plugin.FindingQuery) iter.Seq2[*finding.Finding, error]
	FindingManifest(ctx context.Context, findingID string) (string, error)
	Manifest(ctx context.Context, id string) (*model.Manifest, error)
	ReplaceFinding(ctx context.Context, manifestID string, f *finding.Finding) error
	AddDiagnostic(ctx context.Context, d *report.Diagnostic) error
}

// Finalize applies the policy to every finding of a scan, writes the
// findings whose suppression or rule changed, records the policy
// diagnostics, and returns the gate.
func (e *Evaluator) Finalize(ctx context.Context, s Store) (report.Gate, error) {
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
	if !reflect.DeepEqual(a.Gate, b.Gate) || a.Suppressed() != b.Suppressed() {
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
