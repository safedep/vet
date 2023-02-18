package filter

type filterEvaluationResult struct {
	match   bool
	program *filterProgram
}

func (r *filterEvaluationResult) Matched() bool {
	return r.match
}

func (r *filterEvaluationResult) GetMatchedFilter() *filterProgram {
	if r.program == nil {
		return &filterProgram{}
	}

	return r.program
}
