package filterv2

import (
	policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"
	"github.com/google/cel-go/cel"
)

// FilterProgram holds a rule and its compiled CEL program
// for fast evaluation of the expression
type FilterProgram struct {
	rule    *policyv1.Rule
	program cel.Program
}

func (p *FilterProgram) Name() string {
	return p.rule.GetName()
}

func (p *FilterProgram) GetRule() *policyv1.Rule {
	return p.rule
}