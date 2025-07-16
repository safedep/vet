package filterv2

import policyv1 "buf.build/gen/go/safedep/api/protocolbuffers/go/safedep/messages/policy/v1"

// FilterEvaluationResult represents the result of evaluating a filter
type FilterEvaluationResult struct {
	match   bool
	program *FilterProgram
}

func (r *FilterEvaluationResult) Matched() bool {
	return r.match
}

func (r *FilterEvaluationResult) GetMatchedProgram() *FilterProgram {
	if r.program == nil {
		return &FilterProgram{
			rule: &policyv1.Rule{},
		}
	}

	return r.program
}

func (r *FilterEvaluationResult) GetMatchedRule() *policyv1.Rule {
	return r.GetMatchedProgram().GetRule()
}