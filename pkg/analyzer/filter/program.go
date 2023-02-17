package filter

import "github.com/google/cel-go/cel"

type filterProgram struct {
	name    string
	program cel.Program
}

func (p *filterProgram) Name() string {
	return p.name
}
