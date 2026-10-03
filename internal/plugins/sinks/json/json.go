// Package json is the json format: the report as one JSON document with
// the header, the records and the trailer. It writes one record at a
// time and never holds the report in memory (decisions P6).
package json

import (
	"context"
	"encoding/json"
	"io"

	"github.com/safedep/vet/v2/internal/plugins/internal/render"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/report"
)

// Name is the format name.
const Name = "json"

// Sink writes the json format.
type Sink struct{}

// New builds the sink. It has no options.
func New(cfg plugin.Config) (plugin.Sink, error) {
	if err := cfg.Decode(&struct{}{}); err != nil {
		return nil, err
	}
	return Sink{}, nil
}

// Write writes the report document.
func (Sink) Write(ctx context.Context, r plugin.Report, w io.Writer) error {
	ew := &errWriter{w: w}
	ew.str(`{"header":`)
	ew.value(r.Header())
	ew.str(`,"records":[`)
	first := true
	err := render.EachRecord(ctx, r, func(rec *report.Record) error {
		if !first {
			ew.str(",")
		}
		first = false
		ew.str("\n")
		ew.value(rec)
		return ew.err
	})
	if err != nil {
		return err
	}
	ew.str("\n],\"trailer\":")
	ew.value(r.Trailer())
	ew.str("}\n")
	return ew.err
}

// errWriter keeps the first error, so Write checks it once at the end.
type errWriter struct {
	w   io.Writer
	err error
}

func (e *errWriter) str(s string) {
	if e.err == nil {
		_, e.err = io.WriteString(e.w, s)
	}
}

func (e *errWriter) value(v any) {
	if e.err != nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		e.err = err
		return
	}
	_, e.err = e.w.Write(b)
}
