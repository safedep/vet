package jsonl

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/safedep/vet/v2/internal/engine"
	"github.com/safedep/vet/v2/plugin"
	"github.com/safedep/vet/v2/plugin/plugintest"
	"github.com/safedep/vet/v2/report"
)

func TestStreamGivesTheSameLines(t *testing.T) {
	s, err := New(plugin.MapConfig(nil))
	require.NoError(t, err)
	r := plugintest.SampleReport()
	whole := plugintest.TestSink(t, s, r)

	var streamed bytes.Buffer
	require.NoError(t, engine.WriteOutputs(context.Background(), r, []engine.Output{{Format: Name, Sink: s}}, &streamed))
	assert.Equal(t, string(whole), streamed.String())

	doc, err := report.Read(bytes.NewReader(streamed.Bytes()))
	require.NoError(t, err)
	assert.Equal(t, r.Trailer().RecordCount, uint64(len(doc.Records)))
}
