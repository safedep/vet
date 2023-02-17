package filter

type filterEvaluationResult struct {
	match   bool
	program *filterProgram
}

func (r *filterEvaluationResult) Matched() bool {
	return r.match
}
