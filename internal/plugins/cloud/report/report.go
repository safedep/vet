// Package report is the SafeDep Cloud report sink. It is a stub.
//
// gap G9: the sink maps the report records to the safedep/api findings
// contract, which does not exist yet. Until it does, the sink decodes its
// options, and Check refuses it, so a scan that asks for it stops with a
// usage error before it starts.
package report

import (
	"context"
	"io"

	"github.com/safedep/dry/usefulerror"

	"github.com/safedep/vet/v2/internal/plugins/internal/optschema"
	"github.com/safedep/vet/v2/plugin"
)

// Name is the format name: --report cloud=PATH.
const Name = "cloud"

// CodeUnavailable is the error code of a request for the stub. The command
// exits with code 2.
const CodeUnavailable = "usage_cloud_unavailable"

// Options are the options of the sink, plugins.cloud.options.
type Options struct {
	// Upload sends the report to SafeDep Cloud. Without it, the sink writes
	// the framed protobuf stream to the --report path.
	Upload bool `json:"upload"`
	// Project names the SafeDep Cloud project of the report.
	Project string `json:"project"`
}

// Sink is the stub sink.
type Sink struct{ opts Options }

// New decodes the options.
func New(cfg plugin.Config) (plugin.Sink, error) {
	var o Options
	if err := cfg.Decode(&o); err != nil {
		return nil, err
	}
	return Sink{opts: o}, nil
}

// Check reports that the sink cannot run yet.
func (Sink) Check() error { return ErrUnavailable() }

// Write writes nothing.
func (Sink) Write(context.Context, plugin.Report, io.Writer) error { return ErrUnavailable() }

// OptionsSchema returns the JSON Schema of the options.
func (Sink) OptionsSchema() []byte { return optschema.Of(&Options{}) }

// ErrUnavailable is the error that a request for the sink gets.
func ErrUnavailable() error {
	const msg = "the SafeDep Cloud report plugin is not available yet"
	return usefulerror.NewUsefulError().
		WithCode(CodeUnavailable).
		WithHumanError(msg).
		WithHelp("Use --report json=PATH or --report jsonl=PATH. SafeDep Cloud reads both.").
		WithMsg(msg)
}
