package filter

import "github.com/safedep/vet/gen/filtersuite"

type filterEvaluationResult struct {
	match   bool
	program *filterProgram
}

func (r *filterEvaluationResult) Matched() bool {
	return r.match
}

func (r *filterEvaluationResult) GetMatchedProgram() *filterProgram {
	if r.program == nil {
		return &filterProgram{
			filter: &filtersuite.Filter{},
		}
	}

	return r.program
}

func (r *filterEvaluationResult) GetMatchedFilter() *filtersuite.Filter {
	return r.GetMatchedProgram().GetFilter()
}
