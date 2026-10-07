package policy

import (
	"fmt"
	"slices"
	"time"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/model"
	"github.com/safedep/vet/v2/report"
)

// Options configure an evaluator.
type Options struct {
	// FailOn fails the gate on an unsuppressed finding at this severity or
	// above, or on a finding of an attack control. Empty sets no --fail-on gate.
	FailOn report.FailOn
	// Attacks are the ids of the attack controls, for the attacks
	// --fail-on value.
	Attacks []string
	Now     func() time.Time
}

// Evaluator applies a policy and a --fail-on value to findings.
type Evaluator struct {
	p       *Policy
	failOn  report.FailOn
	attacks []string
	now     time.Time
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
	return &Evaluator{p: p, failOn: o.FailOn, attacks: o.Attacks, now: now().UTC()}
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
// which can be nil. It sets the suppression and the gate record of the
// finding, and clears the values of an earlier evaluation.
func (e *Evaluator) Apply(f *finding.Finding, pkg *model.Package, m *model.Manifest) Outcome {
	var out Outcome
	f.Suppression, f.Gate = nil, nil
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
	var warn *Rule
	var fail []*Rule
	for i := range e.p.Rules {
		r := &e.p.Rules[i]
		ok, err := r.expr.Match(in)
		if err != nil {
			out.Errors = append(out.Errors, fmt.Errorf("rule %s: %w", r.ID, err))
			if r.Action == ActionFail {
				out.BrokenRules = append(out.BrokenRules, r.ID)
				fail = append(fail, r)
			}
			continue
		}
		switch {
		case !ok:
		case r.Action == ActionFail:
			out.FailRules = append(out.FailRules, r.ID)
			fail = append(fail, r)
		case warn == nil:
			warn = r
		}
	}

	if f.Suppressed() {
		out.FailRules, out.BrokenRules = nil, nil
		return out
	}
	failOn := e.failsOn(f)
	out.Fail = len(fail) > 0 || failOn
	f.Gate = gateOf(fail, warn, failOn, e.failOn)
	return out
}

// gateOf builds the gate record of a finding: the fail rules and the
// --fail-on value when one of them fails it, else the first warn rule.
func gateOf(fail []*Rule, warn *Rule, failOn bool, value report.FailOn) *finding.Gate {
	switch {
	case len(fail) > 0 || failOn:
		g := &finding.Gate{Action: finding.GateActionFail}
		for _, r := range fail {
			g.Rules = append(g.Rules, r.ID)
		}
		if failOn {
			g.FailOn = string(value)
		}
		if len(fail) > 0 {
			g.Help, g.Link = fail[0].Help, fail[0].Link
		}
		return g
	case warn != nil:
		return &finding.Gate{Action: finding.GateActionWarn, Rules: []string{warn.ID}, Help: warn.Help, Link: warn.Link}
	}
	return nil
}

// failsOn reports whether the finding meets the --fail-on value.
func (e *Evaluator) failsOn(f *finding.Finding) bool {
	if e.failOn == report.FailOnAttacks {
		return slices.Contains(e.attacks, f.ControlID)
	}
	sev, ok := e.failOn.Severity()
	return ok && f.Severity.AtLeast(sev)
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
