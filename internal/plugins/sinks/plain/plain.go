// Package plain is the plain format: one finding on each line, with tab
// separated fields, for cut and awk. The first line names the fields. A
// suppressed finding is not a line.
package plain

import (
	"context"
	"io"
	"strings"

	"github.com/safedep/vet/v2/finding"
	"github.com/safedep/vet/v2/internal/plugins/sinks/internal/render"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the format name.
const Name = "plain"

var header = []string{"SEVERITY", "CONTROL", "SUBJECT", "WHERE", "FINDING_ID"}

// Sink writes the plain format.
type Sink struct{}

// New builds the sink. It has no options.
func New(cfg plugin.Config) (plugin.Sink, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, err
	}
	return Sink{}, nil
}

// Write writes the header line and one line for each finding.
func (Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	if err := row(w, header); err != nil {
		return err
	}
	return render.EachFinding(ctx, r, func(f *finding.Finding) error {
		if f.Suppressed() {
			return nil
		}
		return row(w, []string{string(f.Severity), f.ControlID, render.SubjectID(f), render.Where(f), f.ID})
	})
}

func row(w io.Writer, cells []string) error {
	for i, c := range cells {
		cells[i] = strings.ReplaceAll(c, "\t", " ")
	}
	_, err := io.WriteString(w, strings.Join(cells, "\t")+"\n")
	return err
}
