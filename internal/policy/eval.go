package policy

import (
	"fmt"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
)

// Options configure an evaluator.
type Options struct {
	// FailOn fails the gate on an unsuppressed finding at this severity or
	// above. Empty sets no severity gate.
	FailOn finding.Severity
	Now    func() time.Time
}

// Evaluator applies a policy and a severity gate to findings.
type Evaluator struct {
	p      *Policy
	failOn finding.Severity
	now    time.Time
	// unavailable holds the errors of the policy sources that did not
	// answer. Finalize records each one as a diagnostic.
	unavailable []string
}

// NewEvaluator returns an evaluator. p can be nil: the built-in default
// policy has no rule (decisions D3).
func NewEvaluator(p *Policy, o Options) *Evaluator {
	if p == nil {
		p = &Policy{}
	}
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	return &Evaluator{p: p, failOn: o.FailOn, now: now().UTC()}
}

// Gated reports whether the user set a gate: a severity or a policy.
func (e *Evaluator) Gated() bool { return e.failOn != "" || len(e.p.Sources) > 0 }

// Outcome is the result of a policy on one finding.
type Outcome struct {
	// Fail means that the finding fails the gate.
	Fail bool
	// FailRules are the fail rules that matched.
	FailRules []string
	// Expired are the expired suppressions that match the finding.
	Expired []string
	// Errors are the rules that failed to evaluate.
	Errors []error
	// BrokenRules are the fail rules that failed to evaluate. Each fails
	// the gate: a rule that cannot run must not let a finding pass.
	BrokenRules []string
}

// Apply evaluates the policy on a finding with its package and manifest,
// which can be nil. It sets the suppression and the policy rule of the
// finding, and clears the values of an earlier evaluation.
func (e *Evaluator) Apply(f *finding.Finding, pkg *model.Package, m *model.Manifest) Outcome {
	var out Outcome
	f.Suppression, f.PolicyRule = nil, ""
	for i := range e.p.Suppressions {
		s := &e.p.Suppressions[i]
		if !s.matches(f) {
			continue
		}
		if s.expires != nil && !e.now.Before(*s.expires) {
			out.Expired = append(out.Expired, s.ref)
			continue
		}
		f.Suppression = &finding.Suppression{Reason: s.Reason, Expires: s.expires, Rule: s.ref}
		break
	}

	in := NewInput(f, pkg, m, e.now)
	var warn string
	for _, r := range e.p.Rules {
		ok, err := r.expr.Match(in)
		if err != nil {
			out.Errors = append(out.Errors, fmt.Errorf("rule %s: %w", r.ID, err))
			if r.Action == ActionFail {
				out.BrokenRules = append(out.BrokenRules, r.ID)
			}
			continue
		}
		if !ok {
			continue
		}
		if r.Action == ActionFail {
			out.FailRules = append(out.FailRules, r.ID)
		} else if warn == "" {
			warn = r.ID
		}
	}
	switch {
	case len(out.FailRules) > 0:
		f.PolicyRule = out.FailRules[0]
	default:
		f.PolicyRule = warn
	}

	if f.Suppressed() {
		out.FailRules, out.BrokenRules = nil, nil
		return out
	}
	out.Fail = len(out.FailRules) > 0 || len(out.BrokenRules) > 0 || (e.failOn != "" && f.Severity.AtLeast(e.failOn))
	return out
}

func (s *Suppression) matches(f *finding.Finding) bool {
	if s.ID != "" && s.ID != f.ID {
		return false
	}
	if s.Control != "" && s.Control != f.ControlID {
		return false
	}
	if s.pkg != nil {
		if f.Subject.Package == nil {
			return false
		}
		id, err := f.Subject.Package.PackageVersion()
		if err != nil {
			return false
		}
		// A suppression PURL with no version matches each version of the
		// package. Both sides compare in the canonical form.
		if s.pkg.RawVersion() == "" {
			return id.SamePackage(*s.pkg)
		}
		return id.Equal(*s.pkg)
	}
	return true
}
