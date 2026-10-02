// Package jsonl is the jsonl format: one JSON object on each line, the
// header first, then each record, then the trailer. Each line carries
// $schema and kind. The sink is a StreamSink, so it holds no record.
package jsonl

import (
	"context"
	"encoding/json"
	"io"

	"github.com/safedep/vet/v2/internal/plugins/internal/render"
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
func (s Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	if err := s.Begin(ctx, r.Header(), w); err != nil {
		return err
	}
	if err := render.EachRecord(ctx, r, func(rec *report.Record) error {
		return s.Record(ctx, rec, w)
	}); err != nil {
		return err
	}
	return s.End(ctx, r.Trailer(), w)
}

// Begin writes the header line.
func (Sink) Begin(_ context.Context, h *report.Header, w io.Writer) error {
	return line(w, report.HeaderLine(h))
}

// Record writes one record line.
func (Sink) Record(_ context.Context, r *report.Record, w io.Writer) error {
	return line(w, report.RecordLine(*r))
}

// End writes the trailer line.
func (Sink) End(_ context.Context, t *report.Trailer, w io.Writer) error {
	return line(w, report.TrailerLine(t))
}

func line(w io.Writer, l report.Line) error {
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

var _ plugin.StreamSink = Sink{}
