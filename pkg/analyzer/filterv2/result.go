package filterv2

import "fmt"

// FilterEvaluationResult represents the result of evaluating a filter
type FilterEvaluationResult struct {
	match   bool
	program *FilterProgram
}

func (r *FilterEvaluationResult) Matched() bool {
	return r.match
}

func (r *FilterEvaluationResult) GetMatchedProgram() (*FilterProgram, error) {
	if r.program == nil {
		return nil, fmt.Errorf("no program available for this result")
	}

	return r.program, nil
}

