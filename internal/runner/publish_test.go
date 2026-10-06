package runner

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/internal/tui/output"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
)

type fakePublisher struct {
	where string
	err   error
	calls int
}

func (*fakePublisher) Write(context.Context, plugin.Report, io.Writer) error { return nil }

func (p *fakePublisher) Publish(context.Context, plugin.Report) (string, error) {
	p.calls++
	return p.where, p.err
}

func TestPublish(t *testing.T) {
	var stdout, stderr bytes.Buffer
	output.SetWriters(&stdout, &stderr)
	output.SetMode(output.Plain)
	t.Cleanup(func() { output.SetMode(output.Rich) })

	ok := &fakePublisher{where: "https://example.com/c/1"}
	failed := &fakePublisher{err: errors.New("no token")}
	file := &fakePublisher{}
	publish(context.Background(), plugintest.SampleReport(), []engine.Output{
		{Format: "ok", Publish: true, Sink: ok},
		{Format: "failed", Publish: true, Sink: failed},
		{Format: "file", Path: "body.md", Sink: file},
	})

	assert.Equal(t, 1, ok.calls)
	assert.Equal(t, 1, failed.calls)
	assert.Equal(t, 0, file.calls, "a file destination does not publish")
	assert.Contains(t, stderr.String(), "vet published the ok report to https://example.com/c/1")
	assert.Contains(t, stderr.String(), "--report failed: no token")
}
