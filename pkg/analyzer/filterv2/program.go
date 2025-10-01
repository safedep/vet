package filterv2

import (
	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	"github.com/google/cel-go/cel"
)

// FilterProgram holds a rule and its compiled CEL program
// for fast evaluation of the expression
type FilterProgram struct {
	policy  *policyv1.Policy
	rule    *policyv1.Rule
	program cel.Program
}

func (p *FilterProgram) Name() string {
	if p.rule == nil {
		return ""
	}

	return p.rule.GetName()
}

func (p *FilterProgram) GetRule() *policyv1.Rule {
	return p.rule
}

func (p *FilterProgram) GetPolicy() *policyv1.Policy {
	return p.policy
}
