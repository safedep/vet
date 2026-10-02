//go:build !cgo

package codeusage

import (
	"context"
	"fmt"

	"github.com/safedep/vet/v2/plugin"
)

// defaultAnalyzer needs tree-sitter, which needs CGO. A static vet build
// has no code analysis.
func defaultAnalyzer(context.Context, string) ([]Evidence, error) {
	return nil, fmt.Errorf("this vet build has no code analysis, because it has no CGO: %w", plugin.ErrUnavailable)
}

// Available reports that this build has code analysis.
func Available() bool { return false }
