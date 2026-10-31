//go:build !cgo

package codeusage

import (
	"context"
	"fmt"

	"github.com/safedep/vet/v2/model"
)

// pythonGraph reads the imports of Python files with tree-sitter, which
// needs CGO. A static vet build has no import graph of a Python manifest.
func (e *Enricher) pythonGraph(_ context.Context, m *model.Manifest) (*model.Graph, error) {
	e.noteGraph(fmt.Sprintf("vet builds no import graph for %s, because this vet build has no CGO", m.Path))
	return nil, nil
}
