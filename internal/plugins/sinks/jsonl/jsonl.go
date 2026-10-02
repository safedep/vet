// Package jsonl is the jsonl format: one JSON object on each line, the
// header first, then each record, then the trailer. Each line carries
// $schema and kind.
package jsonl

import (
	"context"
	"encoding/json"
	"io"

	"github.com/safedep/vet/v2/internal/plugins/sinks/internal/render"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the format name.
const Name = "jsonl"

// Sink writes the jsonl format.
type Sink struct{}

// New builds the sink. It has no options.
func New(cfg plugin.Config) (plugin.Sink, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, err
	}
	return Sink{}, nil
}

// Write writes the report, one line at a time.
func (Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	if err := line(w, report.HeaderLine(r.Header())); err != nil {
		return err
	}
	if err := render.EachRecord(ctx, r, func(rec *report.Record) error {
		return line(w, report.RecordLine(*rec))
	}); err != nil {
		return err
	}
	return line(w, report.TrailerLine(r.Trailer()))
}

func line(w io.Writer, l report.Line) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}
