package filter

import (
	"github.com/google/cel-go/cel"
	"github.com/safedep/vet/gen/filtersuite"
)

// Holds a filter and its compiled CEL program
// for fast evaluation of the expression
type filterProgram struct {
	filter  *filtersuite.Filter
	program cel.Program
}

func (p *filterProgram) Name() string {
	return p.filter.GetName()
}

func (p *filterProgram) GetFilter() *filtersuite.Filter {
	return p.filter
}
